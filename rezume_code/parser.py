import requests
from config import token, ver, vkdom

def get_posts():
    return requests.get(f"https://api.vk.com/method/wall.get", 
                        params={
                            "access_token":token,
                            "v":ver,
                            "domain":vkdom
                        }).json()["response"]["items"]

def get_posts_data():
    posts = get_posts()[0:10]
    data = []
    for i in posts:
        data.append({
                "id":"https://vk.com/aura.servers?w=wall-215889545_" + str(i["id"]),
                "text":i["text"][0:218] + "...",
                "date":i["date"]
                })
    return data    

if __name__ == "__main__":
    posts = get_posts()
    print(posts)
    print("\n\n\n\n")
    posts_data = get_posts_data()
    print(posts_data)