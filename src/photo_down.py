#!/usr/bin/python3.5
#-*- coding: UTF-8 -*-

import vk, os, time
from urllib.request import urlretrieve
import re
r = re.compile('\d+')

def filter_size(key, size):
  result = r.findall(key)
  if result:
    return int(result[0]) > size
  else:
    return False

token = 'e715c3b9e1f6302bfeb5f9e6211c69708bc2c735a074f26031bc71b5b863e3732e1750710a7ca5f17ad40'
#input("Enter a token: ") # vk token


#Authorization
session = vk.Session(access_token=str(token))
vk_api = vk.API(session, v='5.35')

count = 0  # count of down. photos
perc = 0  # percent of down. photos
breaked = 0  # unsuccessful down.
time_now = time.time()  # current time

url = 'https://vk.com/album16975113_000' #"'" + input("Enter a URL of album: ") + "'"  # url of album
folder_name = "/Users/l/vk_photos" #input("Enter a name of folder for download photos: ")  # fold. for photo

print("-------------------------------------------")

owner_id = url.split('album')[1].split('_')[0]  # id of owner
album_id = url.split('album')[1].split('_')[1][0:-1]  # id of album
import pprint
print(owner_id, album_id)
all_albums = vk_api.photos.getAlbums(owner_id=owner_id, album_ids=album_id).get("items", [])

# profile\saved
# if not os.path.exists(os.path.join(folder_name, "profile")):
#   os.makedirs(folder_name + '/' + "profile")  # creating a folder for download photos

# photos = vk_api.photos.get(owner_id=owner_id, album_id="profile", count=1000)

# for i in photos.get('items'):
#   photo_keys = list(filter(lambda x: 'photo' in x and filter_size(x, 600), i.keys()))
#   for key in photo_keys:
#     name = os.path.basename(i.get(key))
#     urlretrieve(i.get(key), folder_name + '/' + "profile" + '/' + str(name)+ str(key) + '.jpg')

for album in all_albums:
  count = album.get('size', 0)
  title = album.get('title')
  album_id = album.get('id')
  photos = vk_api.photos.get(owner_id=owner_id, album_id=album_id, count=1000)  # dictionaries of photos information
  print("A title of album - {}".format(title))
  print("Photos in album - {}".format(count))
  print("------------------")

  if not os.path.exists(os.path.join(folder_name, title)):
      os.makedirs(folder_name + '/' + title)  # creating a folder for download photos
      print("Created a folder for photo album %s." %title)
      print("---------------------------")
  else:
      print("A folder with this name already exists!")
      #exit()

  photos_link = []  #  photos link

  for i in photos.get('items', []):
      photo_keys = list(filter(lambda x: 'photo' in x and filter_size(x, 600), i.keys()))
      for key in photo_keys:
        name = os.path.basename(i.get(key))
        urlretrieve(i.get(key), folder_name + '/' + title + '/' + str(name)+ str(key) + '.jpg')


  print("------------------------")
