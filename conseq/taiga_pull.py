import requests

def get_id_by_name(config, permaname):
    url = config["TAIGA_URL"]
    r = requests.get(url+"/rest/v0/namedDataset", params=dict(fetch="id", name=permaname))
    if r.status_code == 404:
        return None
    return r.text
