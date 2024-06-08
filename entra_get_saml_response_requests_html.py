import argparse
import re

from bs4 import BeautifulSoup, PageElement
from json import dumps, loads
from typing import Optional
from requests import HTTPError
from requests_html import HTMLSession, HTMLResponse
from urllib.parse import urlparse, ParseResult, parse_qsl


def get_start_flow_data(html: str) -> dict:
    result: dict = {}

    soup: BeautifulSoup = BeautifulSoup(html, 'html.parser')

    flow_token_ele: PageElement = soup.find(attrs={'name': 'flowToken'})
    flow_token: str = flow_token_ele.get('value')
    ctx: str = soup.find('input', {'name': 'ctx'}).get('value')
    canary: str = soup.find('input', {'name': 'canary'}).get('value')
    hpgrequestid: str = soup.find('input', {'name': 'hpgrequestid'}).get('value')

    result['flowtoken'] = flow_token
    result['ctx'] = ctx
    result['canary'] = canary
    result['hpgrequestid'] = hpgrequestid

    return result


def parse_config(html: str) -> dict:
    soup_login: BeautifulSoup = BeautifulSoup(html, 'html.parser')
    config_raw: str = soup_login.find(string=re.compile('\$Config'))
    return loads(
        config_raw
        .replace('//<![CDATA[', '')
        .replace('$Config=', '')
        .replace('//]]>', '')
        .replace(';', '')
        .strip()
    )


def get_flow_data(html: str) -> dict:
    result: dict = {}

    config: dict = parse_config(html=html)

    result[config.get('sFTName')] = config.get('sFT')
    result['ctx'] = config.get('sCtx')
    result[config.get('sCanaryTokenName')] = config.get('canary')
    result['hpgrequestid'] = config.get('sessionId')
    result['urlPost'] = config.get('urlPost')

    return result


def start_session(session: HTMLSession, sp_url: str) -> dict:
    result: dict = {}

    resp_start_page: HTMLResponse = session.post(url=sp_url)
    referrer: str = resp_start_page.url
    print(referrer)
    resp_start_page.html.render()
    html_start: str = resp_start_page.html.html
    soup_start: BeautifulSoup = BeautifulSoup(html_start, 'html.parser')
    form: PageElement = soup_start.find('form')
    resp_login: HTMLResponse = session.get(url=form.get('action'))
    resp_login.html.render()
    html_login: str = resp_login.html.html
    soup_login: BeautifulSoup = BeautifulSoup(html_login, 'html.parser')
    next_url: str = soup_login.find('form', {'name': 'f1'}).get('action')

    result.update(get_start_flow_data(html=html_login))
    result['referrer'] = referrer
    result['next_url'] = next_url

    return result


def login(session: HTMLSession, sp_url: str, username: str, password: str) -> dict:
    result: dict = {}
    flow_vals: dict = start_session(session, sp_url)
    next_url_raw: None | str = flow_vals.pop('next_url', None)
    next_url: ParseResult = urlparse(next_url_raw)

    headers: dict[str, str] = dict(session.headers)
    headers['Host'] = next_url.netloc
    headers['Referer'] = flow_vals.pop('referrer', None)
    headers['Origin'] = f'{next_url.scheme}://{next_url.netloc}'

    flow_vals['login'] = username
    flow_vals['loginfmt'] = username
    flow_vals['passwd'] = password
    resp_login: HTMLResponse = session.post(
        url=next_url_raw,
        data=flow_vals,
        headers=headers,
    )
    html_login: str = resp_login.html.html
    flow_vals = get_flow_data(html=html_login)
    # flow_vals['login'] = username
    # flow_vals['loginfmt'] = username
    # flow_vals['passwd'] = password
    url = f'{next_url.scheme}://{next_url.netloc}{flow_vals.pop("urlPost", "")}'
    resp_appverify: HTMLResponse = session.post(
        url=url,
        data=flow_vals,
    )

    flow_vals = get_flow_data(html=resp_appverify.html.html)
    # flow_vals['login'] = username
    # flow_vals['loginfmt'] = username
    # flow_vals['passwd'] = password
    url = f'{next_url.scheme}://{next_url.netloc}{flow_vals.pop("urlPost", "")}'
    resp_kmsi: HTMLResponse = session.post(
        url=url,
        data=flow_vals,
    )
    # print(parse_config(html=resp_kmsi.html.html))
    # return ''

    soup_kmsi: BeautifulSoup = BeautifulSoup(resp_kmsi.html.html, 'html.parser')
    saml_response: str = soup_kmsi.find(attrs={'name': 'SAMLResponse'}).get('value')
    relay_state: str = soup_kmsi.find(attrs={'name': 'RelayState'}).get('value')
    result['saml_response'] = saml_response
    result['relay_state'] = relay_state

    return result


def main(
        sp_url: str,
        username: str,
        password: str,
        proxies: Optional[dict] = None,
) -> str:
    session = HTMLSession()

    session.proxies = proxies

    saml_token: None | str = None
    try:
        saml_token = login(
            session=session,
            sp_url=sp_url,
            username=username,
            password=password,
        )
        return saml_token
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
        print(dumps(data, indent=4))
    else:
        print('No results found')
