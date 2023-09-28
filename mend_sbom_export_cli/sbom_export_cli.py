import time
import argparse
import concurrent
import inspect
import json
import logging
import os
import sys
from importlib import metadata
import requests
import re
import io
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import Tuple
import base64
from mend_sbom_export_cli._version import __version__, __tool_name__, __description__
from mend_sbom_export_cli.const import aliases, varenvs

logger = logging.getLogger(__tool_name__)
logger.setLevel(logging.DEBUG)
try:
    is_debug = logging.DEBUG if os.environ.get("DEBUG").lower() == 'true' else logging.INFO
except:
    is_debug = logging.INFO

formatter = logging.Formatter('[%(asctime)s] %(levelname)5s %(message)s', "%Y-%m-%d %H:%M:%S")
s_handler = logging.StreamHandler()
s_handler.setFormatter(formatter)
s_handler.setLevel(is_debug)
logger.addHandler(s_handler)
logger.propagate = False

APP_TITLE = "Mend SBOM Cli"
API_VERSION = "1.4"
try:
    APP_VERSION = metadata.version(f'mend_{__tool_name__}') if metadata.version(f'mend_{__tool_name__}') else __version__
except:
    APP_VERSION = __version__

args = None
short_lst_prj = []
token_pattern = r"^[0-9a-zA-Z]{64}$"
uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
AGENT_INFO = {"agent": f"ps-{__tool_name__.replace('_', '-')}", "agentVersion": APP_VERSION}


def try_or_error(supplier, msg):
    try:
        return supplier()
    except:
        return msg


def fn():
    fn_stack = inspect.stack()[1]
    return f'{fn_stack.function}:{fn_stack.lineno}'


def ex():
    e_type, e_msg, tb = sys.exc_info()
    return f'{tb.tb_frame.f_code.co_name}:{tb.tb_lineno}'


def log_obj_props(obj, obj_title=""):
    masked_props = ["ws_user_key", "user_key"]
    prop_list = [obj_title] if obj_title else []
    try:
        obj_dict = obj if obj is dict else obj.__dict__
        for k in obj_dict:
            v = "******" if k in masked_props else obj_dict[k]
            prop_list.append(f'{k}={v}')
        logger.debug("\n\t".join(prop_list))
    except Exception as err:
        logger.error(f'[{fn()}] Failed: {err}')


def check_patterns():
    res = []
    if not (re.match(uuid_pattern, args.ws_user_key) or re.match(token_pattern, args.ws_user_key)):
        res.append("MEND_USERKEY")
    if not (re.match(uuid_pattern, args.ws_token) or re.match(token_pattern, args.ws_token)):
        res.append("MEND_APIKEY")
    if args.producttoken:
        prods = args.producttoken.split(",")
        for prod_ in prods:
            if not (re.match(uuid_pattern, prod_) or re.match(token_pattern, prod_)):
                res.append("MEND_PRODUCTTOKEN")
                break
    if args.projecttoken:
        projs = args.projecttoken.split(",")
        for proj_ in projs:
            if not (re.match(uuid_pattern, proj_) or re.match(token_pattern, proj_)):
                res.append("MEND_PROJECTTOKEN")
                break
    if args.exclude:
        excludes = args.exclude.split(",")
        for excl_ in excludes:
            if not (re.match(uuid_pattern, excl_) or re.match(token_pattern, excl_)):
                res.append("MEND_EXCLUDETOKEN")
                break
    return res


def get_project_list():
    def get_prj_name(token):
        data_prj = json.dumps({
            "requestType": "getProjectVitals",
            "userKey": args.ws_user_key,
            "projectToken": token
        })
        res = json.loads(call_ws_api(data=data_prj))
        return try_or_error(lambda: f'{res["projectVitals"][0]["productName"]}:{res["projectVitals"][0]["name"]}', try_or_error(lambda: res["errorMessage"],
                                                      f"Internal error during getting project data by token {token}"))

    res = []
    if args.projecttoken:
        res.extend([{x: get_prj_name(x)} for x in args.projecttoken.split(",")])

    if args.producttoken:
        products = args.producttoken.split(",")
        for product_ in products:
            data_prj = json.dumps(
                {"requestType": "getAllProjects",
                 "userKey": args.ws_user_key,
                 "productToken": product_,
                 })
            try:
                prj_data = json.loads(call_ws_api(data=data_prj))["projects"]
                res.extend([{x["projectToken"]: get_prj_name(x["projectToken"])} for x in prj_data])  # x["projectName"]
            except Exception as err:
                pass
    elif not args.projecttoken:
        data_prj = json.dumps(
            {"requestType": "getOrganizationProjectVitals",
             "userKey": args.ws_user_key,
             "orgToken": args.ws_token,
             })
        try:
            prj_data = json.loads(call_ws_api(data=data_prj))["projectVitals"]
            res.extend([{x["token"]: get_prj_name(x["token"])} for x in prj_data])  # x["name"]
        except:
            pass

    exclude_tokens = []
    if args.exclude:
        excludes = args.exclude.split(",")
        for exclude_ in excludes:
            data_prj = json.dumps(
                {"requestType": "getAllProjects",
                 "userKey": args.ws_user_key,
                 "productToken": exclude_,
                 })
            try:
                prj_data = json.loads(call_ws_api(data=data_prj))["projects"]
                exclude_tokens.extend([{x["projectToken"]: get_prj_name(x["projectToken"])} for x in prj_data])  #  x["projectName"]
            except:
                exclude_tokens.append(exclude_)
        res = list(set(res) - set(exclude_tokens))
    return res


def call_ws_api(data, header={"Content-Type": "application/json"}, method="POST", download=False):
    global args
    data_json = json.loads(data)
    data_json["agentInfo"] = AGENT_INFO
    try:
        res_ = requests.request(
            method=method,
            url=f"{extract_url(args.ws_url)}/api/v{API_VERSION}",
            data=json.dumps(data_json),
            headers=header, )
        if download:
            res = res_.content if res_.status_code == 200 else ""
        else:
            res = res_.text if res_.status_code == 200 else ""

    except Exception as err:
        res = f"Error was raised. {err}"
        logger.error(f'[{ex()}] {err}')
    return res


def parse_args():
    parser = argparse.ArgumentParser(description=__description__)
    parser.add_argument(*aliases.get_aliases_str("userkey"), help="Mend user key", dest='ws_user_key',
                        default=varenvs.get_env("wsuserkey"), required=not varenvs.get_env("wsuserkey"))
    parser.add_argument(*aliases.get_aliases_str("apikey"), help="Mend API key", dest='ws_token',
                        default=varenvs.get_env("wsapikey"), required=not varenvs.get_env("wsapikey"))
    parser.add_argument(*aliases.get_aliases_str("productkey"), help="Mend product scope", dest='producttoken',
                        default=varenvs.get_env("wsproduct"))
    parser.add_argument(*aliases.get_aliases_str("projectkey"), help="Mend project scope", dest='projecttoken',
                        default=varenvs.get_env("wsproject"))
    parser.add_argument(*aliases.get_aliases_str("exclude"), help="Exclude Mend project/product scope", dest='exclude',
                        default=varenvs.get_env("wsexclude"))
    parser.add_argument(*aliases.get_aliases_str("output"), help="Output directory", dest='out_dir', default=os.getcwd())
    parser.add_argument(*aliases.get_aliases_str("url"), help="Mend server URL", dest='ws_url',
                        default=varenvs.get_env("wsurl"), required=not varenvs.get_env("wsurl"))
    parser.add_argument(*aliases.get_aliases_str("lic"), help="Include license text for each project", dest='lictext',
                        default="false")
    parser.add_argument(*aliases.get_aliases_str("threads"), help="Number of threads", dest='threads',
                        default=10)
    parser.add_argument(*aliases.get_aliases_str("type"), help="Report type (SPDX or CDX)", dest='type', default="spdx")
    arguments = parser.parse_args()

    return arguments


def extract_url(url: str) -> str:
    url_ = url if url.startswith("https://") else f"https://{url}"
    url_ = url_.replace("http://", "")
    pos = url_.find("/", 8)  # Not using any suffix, just direct url
    return url_[0:pos] if pos > -1 else url_


def get_lic_text_from_data_attr_cdx(data):
    res = []
    for key, value in data.items():
        for el_ in value:
            for lic_ in el_["licenses"]:
                license_text = lic_["licenseText"] if lic_["licenseText"] else lic_["license"]
                res.append({
                    f'SPDXRef-PACKAGE-{el_["library"]}::{lic_["license"]}' : license_text
                })
    return res


def get_lic_text_from_data_attr_spdx(data):
    res = []
    for key, value in data.items():
        for el_ in value:
            license_text = ""
            for lic_ in el_["licenses"]:
                license_text += "\n" if license_text else ""
                license_text += lic_["licenseText"] if lic_["licenseText"] else lic_["license"]
            if license_text:
                res.append({
                    f'SPDXRef-PACKAGE-{el_["library"]}' : license_text
                })
    return res


def get_lic_list() -> dict:
    global res_lic
    res_lic = dict()

    def generic_thread_lic_text(ent_l: list, worker: callable) -> Tuple[list, list]:
        data = []
        errors = []

        with ThreadPoolExecutor(max_workers=PROJECT_PARALLELISM_LEVEL) as executer:
            futures = [executer.submit(worker, ent) for ent in ent_l]

            for future in concurrent.futures.as_completed(futures):
                try:
                    temp_l = future.result()
                    if temp_l:
                        data.extend(temp_l)
                except Exception as e:
                    errors.append(e)
                    logger.error(f"Error on future: {future.result()}")

        return data, errors

    def get_lic_text(prj):
        try:
            for key, value in prj.items():
                data_prj = json.dumps({
                    "requestType": "getProjectAttributionReport",
                    "userKey": args.ws_user_key,
                    "projectToken": key,
                    "reportingAggregationMode": "BY_PROJECT",
                    "reportingScope" : "LICENSES",
                    "exportFormat": "JSON"
                })
            data = json.loads(call_ws_api(data=data_prj))["detail"]
            if args.type.lower() == "spdx":
                for res_lic_ in get_lic_text_from_data_attr_spdx(data=data):
                    res_lic.update(res_lic_)
            elif args.type.lower() == "cdx":
                for res_lic_ in get_lic_text_from_data_attr_cdx(data=data):
                    res_lic.update(res_lic_)
        except Exception as err:
            pass
    generic_thread_lic_text(ent_l=short_lst_prj, worker=get_lic_text)
    return res_lic


def create_sbom_prj(token: str):
    data_sbom = json.dumps({
        "requestType": "getProjectSpdxReport",
        "userKey": args.ws_user_key,
        "projectToken": token,
        "format":"JSON"
    })
    return try_or_error(lambda: json.loads(call_ws_api(data=data_sbom)), [])


def create_cyclone(prj_: str):
    for key, value in prj_.items():
        token = key
    data_sbom = json.dumps({
        "requestType": "generateProjectReportAsync",
        "projectToken": token,
        "userKey": args.ws_user_key,
        "reportType": "ProjectSBOMReport",
        "standard": "CycloneDX",
        "format": "json"
    })
    res = try_or_error(lambda: json.loads(call_ws_api(data=data_sbom)), [])
    try:
        uuid = res["asyncProcessStatus"]["uuid"]
        data_status = json.dumps(
            {
                "requestType": "getAsyncProcessStatus",
                "orgToken": args.ws_token,
                "userKey": args.ws_user_key,
                "uuid": uuid
            }
        )
        res_status = ""
        while res_status != "SUCCESS" and res_status != "FAILED":
            time.sleep(5)
            status = try_or_error(lambda: json.loads(call_ws_api(data=data_status)), [])
            try:
                res_status = status["asyncProcessStatus"]["status"]
            except Exception as err:
                try:
                    err_status = status["errorMessage"]
                    res_status = "FAILED"
                except:
                    err_status = "Unexpected error"
                    res_status = "FAILED"
        if res_status == "SUCCESS":
            data_download = json.dumps(
                {
                    "requestType": "downloadAsyncReport",
                    "orgToken": args.ws_token,
                    "userKey": args.ws_user_key,
                    "reportStatusUUID": uuid
                }
            )
            status_download = try_or_error(lambda: call_ws_api(data=data_download, download=True), [])
            if status_download:
                zip_bytesio = io.BytesIO(status_download)
                with zipfile.ZipFile(zip_bytesio, 'r') as zip_ref:
                    zip_file_contents = zip_ref.namelist()
                    for file_name in zip_file_contents:
                        with zip_ref.open(file_name) as file:
                            file_content = file.read()
                            json_content_str = file_content.decode('utf-8')
                            cdx_data = json.loads(json_content_str)
                            rep_name = zip_file_contents[0]
            else:
                cdx_data = {}
                rep_name = ""
        else:
            logger.error(f"Downloading status is FAILED: {try_or_error(lambda: err_status, '')}. Please, repeat later")
            cdx_data = {}
            rep_name = ""

        for i, el_ in enumerate(cdx_data["components"]):
            lic_txt = []
            for license_ in el_["licenses"]:
                license_name = try_or_error(lambda: license_['license']['id'], '')
                if(license_name == ''):
                    license_name = try_or_error(lambda: license_['license']['name'], '')
                lic_text = lic_texts.get(f"SPDXRef-PACKAGE-{el_['name']}::{license_name}")
                lic_text = lic_text if lic_text else lic_texts.get(f"SPDXRef-PACKAGE-{el_['name']}::{try_or_error(lambda: license_name.replace('-',' ').replace('_',' '), '')}")
                if lic_text is not None:
                    lic_text_new = base64.b64encode(lic_text.encode('utf-8')).decode('utf-8')
                    lic_txt.append(
                        {
                            "license": {
                                "name": f"{license_name}",
                                "text": {
                                    "contentType": "text/plain",
                                    "encoding": "base64",
                                    "content": f"{lic_text_new}"
                                }
                            }
                        }
                    )
            if lic_txt:
                cdx_data["components"][i].update({
                    "evidence": {
                        "licenses": lic_txt
                    }
                })
    except BaseException as err:
        pass

    if rep_name:
        full_path = os.path.join(args.out_dir, rep_name)
        with open(full_path, 'w', encoding='utf-8') as json_file:
            json.dump(cdx_data, json_file, indent=4, ensure_ascii=False)
        return f"The report file {rep_name} was created."
    else:
        return "The creation report file was failed."


def main():
    def generic_thread_write_rep(ent_l: list, worker: callable) -> list:
        errors = []

        with ThreadPoolExecutor(max_workers=PROJECT_PARALLELISM_LEVEL) as executer:
            futures = [executer.submit(worker, ent) for ent in ent_l]

            for future in concurrent.futures.as_completed(futures):
                try:
                    temp_l = future.result()
                    if temp_l:
                        logger.info(temp_l)
                except Exception as e:
                    errors.append(e)
                    logger.error(f"Error on future: {future.result()}")

        return errors

    def create_spdx(prj_):
        for key, value in prj_.items():
            sbom_prj = create_sbom_prj(token=key)
            rep_name = f"SPDX report for {value.split(':')[1]}.json"
            rep_name = rep_name.replace("/","_")
            full_path = os.path.join(args.out_dir, rep_name)
            try:
                set_spdx_values = set(item['SPDXID'] for item in sbom_prj["packages"])
                result = [key_ for key_ in lic_texts.keys() if key_ in set_spdx_values]
                for lic_lib in result:
                    lic_text = lic_texts.get(lic_lib)
                    if sbom_prj.get("hasExtractedLicensingInfos") is None:
                        sbom_prj["hasExtractedLicensingInfos"] = []
                    sbom_prj["hasExtractedLicensingInfos"].append({
                        "licenseId": lic_lib.replace('SPDXRef-PACKAGE-', 'LicenseRef-'),
                        "extractedText": lic_text,
                        "name": lic_lib.replace('SPDXRef-PACKAGE-', 'LicenseRef-'),
                    })
            except Exception as err:
                pass

            with open(full_path, 'w', encoding='utf-8') as json_file:
                json.dump(sbom_prj, json_file, indent=4, ensure_ascii=False)
            return f"The report file {rep_name} was created."
        return ""

    global args
    global PROJECT_PARALLELISM_LEVEL
    global short_lst_prj
    global lic_texts

    hdr_title = f'{APP_TITLE} {__version__}'
    hdr = f'\n{len(hdr_title)*"="}\n{hdr_title}\n{len(hdr_title)*"="}'
    print(hdr)
    PROJECT_PARALLELISM_LEVEL = try_or_error(lambda: int(args.threads), 10)
    try:
        args = parse_args()
        chp_ = check_patterns()
        if chp_:
            logger.error("Missing or malformed configuration parameters:")
            [logger.error(el_) for el_ in chp_]
            exit(-1)

        logger.info("Starting to create reports...")
        short_lst_prj = get_project_list()
        lic_texts = get_lic_list() if args.lictext.lower() == "true" else {}
        if not os.path.exists(args.out_dir):
            logger.info(f"Dir: {args.out_dir} does not exist. Creating it")
            os.mkdir(args.out_dir)

        if args.type.lower() == "spdx":
            generic_thread_write_rep(ent_l=short_lst_prj, worker=create_spdx)
        elif args.type.lower() == "cdx":
            generic_thread_write_rep(ent_l=short_lst_prj, worker=create_cyclone)
        else:
            logger.error(f"The type {args.type} is not supported.")
            exit(-1)
    except Exception as err:
        logger.error(f'[{fn()}] Failed to create report files: {err}')
        exit(-1)


if __name__ == '__main__':
    sys.exit(main())
