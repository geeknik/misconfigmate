#!/usr/bin/env python3
import requests
import argparse
import json
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn, BarColumn, TaskProgressColumn
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
import logging
import random
import sys

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
console = Console()

# Constants
SUFFIXES = [
    'dev', 'staging', 'stage', 'test', 'prod', 'qa',
    'internal', 'corp', 'team',
    'app', 'api', 'admin',
    'us', 'eu', 'asia'
]

PREFIXES = [
    'dev',
    'staging',
    'test',
    'qa',
    'admin',
    'internal'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0'
]

class MisconfigMapper:
    def __init__(self, args):
        self.target = args.target.lower().strip()
        self.service = args.service
        self.delay = args.delay
        self.headers = self._parse_headers(args.headers)
        self.skip_checks = args.skip_checks
        self.verbose = args.verbose
        self.timeout = args.timeout
        self.output_format = args.output
        self.webhook_url = args.webhook
        self.threads = args.threads
        self.discovered = 0
        self.errors = 0

        # Add random user agent if none specified
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = random.choice(USER_AGENTS)

        if self.verbose:
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)

        self.services = self._load_services()

    def _parse_headers(self, headers_str):
        if not headers_str:
            return {}
        headers = {}
        try:
            for header in headers_str.split(';;'):
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        except Exception as e:
            logging.error(f"Error parsing headers: {e}")
        return headers

    def _load_services(self):
        try:
            with open('templates/services.json', 'r') as f:
                services = json.load(f)
                if self.service != '*':
                    services = [s for s in services if str(s.get('id')) == self.service or s.get('metadata', {}).get('service') == self.service]
                    if not services:
                        console.print(f"[red]Error: No service found matching '{self.service}'[/]")
                        sys.exit(1)
                logging.debug(f"Loaded {len(services)} service templates")
                return services
        except FileNotFoundError:
            console.print("[red]Error: services.json not found. Run with --update-templates first[/]")
            sys.exit(1)
        except json.JSONDecodeError:
            console.print("[red]Error: services.json is malformed[/]")
            sys.exit(1)

    def _check_endpoint(self, url, service):
        try:
            actual_url = url.replace('{TARGET}', self.target)

            response = requests.request(
                method=service['request']['method'],
                url=actual_url,
                headers={**self.headers, **service.get('request', {}).get('headers', {})},
                verify=False,
                timeout=self.timeout,
                allow_redirects=True
            )

            exists = any(fp in response.text for fp in service['response']['detectionFingerprints'])

            vulnerable = False
            if not self.skip_checks and exists:  # Only check vulnerability if service exists
                status_match = False
                if isinstance(service['response']['statusCode'], list):
                    status_match = response.status_code in service['response']['statusCode']
                else:
                    status_match = response.status_code == service['response']['statusCode']

                vulnerable = (
                    status_match and
                    any(fp in response.text for fp in service['response']['fingerprints'])
                )

            if exists or vulnerable:
                self.discovered += 1
                return {
                    'timestamp': datetime.now().isoformat(),
                    'target': self.target,
                    'url': actual_url,
                    'exists': exists,
                    'vulnerable': vulnerable,
                    'service': service['metadata']['serviceName'],
                    'description': service['metadata']['description'],
                    'reproduction_steps': service['metadata'].get('reproductionSteps', []),
                    'references': service['metadata'].get('references', []),
                    'status_code': response.status_code
                }

        except Exception as e:
            self.errors += 1
            if self.verbose:
                logging.debug(f"Error checking {url}: {str(e)}")
            return None

    def generate_permutations(self, base_name):
        """Generate realistic subdomain permutations"""
        permutations = set()

        # Base name
        permutations.add(base_name)

        # Common patterns
        for suffix in SUFFIXES:
            permutations.add(f"{base_name}-{suffix}")
            permutations.add(f"{base_name}.{suffix}")

        for prefix in PREFIXES:
            permutations.add(f"{prefix}{base_name}")
            permutations.add(f"{prefix}.{base_name}")

        return list(permutations)

    def generate_urls(self):
        """Generate target URLs based on service templates and permutations"""
        urls = []
        permutations = self.generate_permutations(self.target)

        for service in self.services:
            for domain in permutations:
                for path in service['request']['path']:
                    url = service['request']['baseURL'].replace('{TARGET}', domain)
                    if not url.startswith(('http://', 'https://')):
                        url = f"https://{url}"
                    url = f"{url.rstrip('/')}/{path.lstrip('/')}"
                    urls.append((url, service))

        if self.verbose:
            logging.debug(f"Generated {len(urls)} URLs to test")

        return urls

    def _format_output(self, results):
        if not results:
            return None

        if self.output_format == 'json':
            return json.dumps(results, indent=2)

        elif self.output_format == 'jsonl':
            return '\n'.join(json.dumps(r) for r in results)

        elif self.output_format == 'csv':
            import csv
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
            return output.getvalue()

        elif self.output_format == 'webhook':
            webhook_data = {
                'timestamp': datetime.now().isoformat(),
                'target': self.target,
                'findings': results
            }
            try:
                requests.post(self.webhook_url, json=webhook_data)
                return "Results sent to webhook successfully"
            except Exception as e:
                return f"Error sending to webhook: {str(e)}"

        return None

    def _display_table(self, results):
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Service", style="blue")
        table.add_column("URL", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Description", style="yellow", width=100)

        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        for r in results:
            key = (r['service'], r['url'])
            if key not in seen:
                seen.add(key)
                unique_results.append(r)

        for result in unique_results:
            status = []
            if result['exists']:
                status.append("[cyan]EXISTS[/]")
            if result['vulnerable']:
                status.append("[red]VULNERABLE[/]")

            table.add_row(
                result['service'],
                result['url'],
                " & ".join(status),
                result['description']
            )

        console.print("\n[green]Scan Results:[/]")
        console.print(table)
        console.print(f"\nFound {len(unique_results)} unique results.")
        console.print(f"Total discovered endpoints: {self.discovered}")
        if self.errors > 0:
            console.print(f"Encountered {self.errors} errors during scanning.\n")

    def scan(self):
        urls = self.generate_urls()
        results = []

        # Custom progress bar format
        progress = Progress(
            SpinnerColumn(),
            "[progress.description]{task.description}",
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            "Endpoints: {task.completed}/{task.total}",
            "•",
            TimeElapsedColumn(),
            "•",
            "Discovered: {task.fields[discovered]}",
            transient=True
        )

        with progress:
            task = progress.add_task(
                f"[cyan]Scanning target: {self.target}",
                total=len(urls),
                discovered=0
            )

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                def process_url(args):
                    url, service = args
                    if self.delay:
                        time.sleep(self.delay/1000)
                    result = self._check_endpoint(url, service)
                    progress.update(task,
                                  advance=1,
                                  discovered=self.discovered,
                                  refresh=True)
                    return result

                # Process URLs in smaller batches for more granular progress updates
                batch_size = max(1, min(10, len(urls) // 20))  # Adjust batch size based on total URLs
                url_batches = [urls[i:i + batch_size] for i in range(0, len(urls), batch_size)]

                for batch in url_batches:
                    batch_results = list(executor.map(process_url, batch))
                    results.extend([r for r in batch_results if r is not None])

        if self.output_format and self.output_format != 'table':
            formatted_output = self._format_output(results)
            if formatted_output:
                print(formatted_output)
        else:
            self._display_table(results)

def main():
    parser = argparse.ArgumentParser(description='Misconfig Mapper - Find service misconfigurations')
    parser.add_argument('-target', required=True, help='Target domain or company name')
    parser.add_argument('-service', default='*', help='Service ID or * for all')
    parser.add_argument('-skip-checks', action='store_true', help='Only detect services without checking misconfigs')
    parser.add_argument('-headers', help='Request headers (format: "Key: Value;; Key2: Value2")')
    parser.add_argument('-delay', type=int, default=0, help='Delay between requests in ms')
    parser.add_argument('-timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-verbose', action='store_true', help='Show detailed output')
    parser.add_argument('-output', choices=['table', 'json', 'jsonl', 'csv', 'webhook'],
                       default='table', help='Output format')
    parser.add_argument('-webhook', help='Webhook URL for sending results')
    parser.add_argument('-threads', type=int, default=5, help='Number of concurrent threads')

    args = parser.parse_args()

    if args.output == 'webhook' and not args.webhook:
        console.print("[red]Error: Webhook URL required when using webhook output format[/]")
        return

    try:
        scanner = MisconfigMapper(args)
        scanner.scan()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
