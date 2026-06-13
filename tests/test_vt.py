#from src.virustotal import check_url_virustotal

#url = "http://secure-bank-login-verify.xyz"
#result = check_url_virustotal(url)

#print(result)

from src.virustotal import check_url_virustotal

print(
    check_url_virustotal(
        "https://google.com"
    )
)