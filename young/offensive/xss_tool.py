import requests
from bs4 import BeautifulSoup
import time
import json
import re
from datetime import datetime
import random
import base64

class XSSAttackTool:
    def __init__(self, target_url, attacker_server):
        self.target_url = target_url.rstrip('/')
        self.attacker_server = attacker_server.rstrip('/')
        self.session = requests.Session()
        self.logged_in = False
        