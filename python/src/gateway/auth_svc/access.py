import os
import requests


def login(request):
    auth = request.authorization
    if not auth:
        return None, ("Missing Credentials", 401)
    basicAuth = (auth.username, auth.password)
    response = requests.post(
        f"http://{os.environ.get('AUTH_SVC_ADDRESS')}/login",
        auth=basicAuth
    )

    if response.status_code == 200:
        return response.text, None
    return None, (response.text, response.status_code)
