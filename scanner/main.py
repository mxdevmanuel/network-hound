# TODO: Migrate from os.path to pathlib
import argparse
import logging
import nmap
import os
import requests
import sys
import tomllib

CONFIG_FILE = 'settings.toml'
REPORT_IPV4_ENDPOINT = '/ipv4-report'
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(prog='HoundScanner',
                                     description='''
                                     Service to scan local network and deliver
                                     results to hound server
                                     ''')
    # TODO: Add arguments to override config file or something
    parser.add_argument('-c', '--config-file')

    args = parser.parse_args()

    config_file = args.config_file

    if config_file is None:
        config_file = find_config_file()
    elif not os.access(config_file, os.R_OK):
        logger.error('Specified config file unavailable')
        config_file = None

    if config_file is None:
        logger.error('No config file specified or found')
        sys.exit(1)

    config = {}
    with open(config_file, 'rb') as f:
        config = tomllib.load(f)

    logging.basicConfig(filename='scanner.log', level=logging.DEBUG)

    if config['ipv4-address'] is not None:
        report = scan_ipv4(config['ipv4-address'])
        report = transform_ipv4_payload(report)
        logger.debug(report)
        url = f'{config["hound-server"]}{REPORT_IPV4_ENDPOINT}'
        server_call(url, report)


def find_config_file():
    # Same dir
    this_dir = os.path.dirname(__file__)

    this_config_file = os.path.join(this_dir, CONFIG_FILE)

    if os.access(this_config_file, os.R_OK):
        return this_config_file
    # TODO: possible different scenarios like home or something
    return None


def scan_ipv4(ipv4_address):
    try:
        nm = nmap.PortScanner()
        return nm.scan(hosts=ipv4_address, arguments='-sn --privileged')
    except Exception as e:
        raise e


def transform_ipv4_payload(ipv4_scan):
    result = {}
    if 'nmap' in ipv4_scan:
        result['scanstats'] = ipv4_scan['nmap']['scanstats']

    if 'scan' in ipv4_scan and type(ipv4_scan['scan']) is dict:
        scans = []
        for k in ipv4_scan['scan']:
            scan = {}
            scan['hostname'] = ipv4_scan['scan'][k]['hostnames'][0]['name']
            scan['hosttype'] = ipv4_scan['scan'][k]['hostnames'][0]['type']
            scan['ipv4'] = ipv4_scan['scan'][k]['addresses']['ipv4']
            scan['mac'] = ipv4_scan['scan'][k]['addresses'].get('mac', '')
            scan['vendor'] = ipv4_scan['scan'][k]['vendor'].get(
                scan['mac'], '')
            scan['status'] = ipv4_scan['scan'][k]['status']['state']
            scan['status_reason'] = ipv4_scan['scan'][k]['status']['reason']
            scans.append(scan)

        result['scans'] = scans

    return result


def server_call(url, payload):
    try:
        response = requests.put(url, json=payload)
        logger.debug(f'IPv4 Report Status Code: {response.status_code}')
        logger.debug(f'body: {response.json()}')
    except Exception as e:
        raise e


if __name__ == "__main__":
    main()
