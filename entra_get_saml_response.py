import argparse
import re

from bs4 import BeautifulSoup, PageElement
from json import loads
from typing import Optional
from requests import HTTPError
from requests import Session, Response
from urllib.parse import urlparse, ParseResult


def parse_config(html: str) -> Optional[dict]:
    soup_login: BeautifulSoup = BeautifulSoup(html, 'html.parser')
    cdata_config: str = soup_login.find(string=re.compile(r'\$Config'))
    if not cdata_config:
        return None
    config_raw: str = (
        cdata_config
        .replace('//<![CDATA[', '')
        .replace('$Config=', '')
        .replace('//]]>', '')
        .replace(';', '')
        .strip()
    )

    return loads(config_raw)


def get_flow_data(html: str) -> dict:
    result: dict = {}

    config: dict = parse_config(html=html)
    url_no_cookies: str = config.get('urlNoCookies')
    parsed_url: ParseResult = urlparse(url_no_cookies)
    base_url: str = f'{parsed_url.scheme}://{parsed_url.netloc}'

    result[config.get('sFTName')] = config.get('sFT')
    result['ctx'] = config.get('sCtx')
    result[config.get('sCanaryTokenName')] = config.get('canary')
    result['hpgrequestid'] = config.get('sessionId')
    next_url: str = f'{base_url}{config.get("urlPost")}'
    result['urlPost'] = next_url

    return result


def get_saml_response(session: Session, sp_url: str, username: str, password: str) -> str:
    result: Optional[str] = None

    url: str = sp_url
    flow_data: dict = {}
    request_limit: int = 10

    while not result and request_limit:
        response: Response = session.post(
            url=url,
            data=flow_data,
        )
        request_limit -= 1
        soup: BeautifulSoup = BeautifulSoup(response.text, 'html.parser')
        saml_response: PageElement = soup.find(attrs={'name': 'SAMLResponse'})
        if saml_response:
            result: str = saml_response.get('value')
            break
        else:
            flow_data = get_flow_data(html=response.text)
            url = flow_data.get("urlPost", "")
            flow_data['login'] = username
            flow_data['loginfmt'] = username
            flow_data['passwd'] = password

    return result


def main(
        sp_url: str,
        username: str,
        password: str,
        proxies: Optional[dict] = None,
) -> str:
    session = Session()

    session.proxies = proxies

    try:
        result: str = get_saml_response(
            session=session,
            sp_url=sp_url,
            username=username,
            password=password,
        )
        return result
    except HTTPError as http_err:
        print(f'HTTPError during logon: {http_err}')
        raise
    except Exception as exc_auth:
        print(f'Unexpected error during logon: {exc_auth}')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--sp_url',
        type=str,
        required=True,
        help="The URL of the service you want to authenticate to...",
    )
    parser.add_argument(
        '--username',
        type=str,
        required=True,
        help='The user name for your MS Entra account',
    )
    parser.add_argument(
        '--password',
        type=str,
        required=True,
        help='The password for your MS Entra account',
    )
    parser.add_argument(
        '--proxies',
        type=str,
        required=False,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
    )

    args = parser.parse_args()

    proxies: Optional[dict] = None
    if proxies:
        try:
            proxies: dict = loads(args.proxies)
        except Exception as exc_json:
            print(f'WARNING: failure parsing proxies: {exc_json}: proxies provided: {proxies}')

    if data := main(
        sp_url=args.sp_url,
        username=args.username,
        password=args.password,
        proxies=proxies,
    ):
        print(data)
    else:
        print('No results found')
