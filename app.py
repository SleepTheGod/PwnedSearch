from flask import Flask, render_template, request, jsonify
import requests

app = Flask(__name__)

# Your Info class for checking breaches and emails
class Info:
    def __init__(self, query, lookuptype):
        self.query = query
        self.lookuptype = lookuptype.lower()
        self.apikey = "230d5357faf1155187111d8236a4204d324d5398"
        self.emailrepkey = "kanmzsmlkhwfcw5nge0f4z64dxgr3dj3btho9bimqw8g2bak"

    def parse_breach(self, data):
        return data.replace("{'success': True, 'found': ","").replace(", 'result': [{'line': '","").replace(", {'line': '","").replace("{","").replace("}","").replace("]","").replace("'","\n").replace(", u","").replace("line","").replace(": u","").replace(": [u","").replace("result","").replace("success","").replace("found","")

    def strip_data(self, data):
        return data.replace('"result":[{"line":"',"").replace('"',"").replace("{","").replace("}","").replace("]","").replace("[","").replace("line:","")

    def lookup(self):
        if self.lookuptype == "email":
            self.check_breaches()
            self.check_email_rep()
        elif self.lookuptype == "ip":
            self.ip_to_addr()
            return

        req = requests.post(f"https://leakcheck.net/api/?key={self.apikey}&check={self.query}&type={self.lookuptype}")
        
        if "false" in req.text:
            return None

        user_and_passwords = []
        self.passwords = []
        get = req.text.split(",")
        for g in get:
            new = self.strip_data(g)
            self.passwords.append(new)

    def check_breaches(self):
        self.breaches = []
        b = webdriver.Chrome()
        b.get(f'https://haveibeenpwned.com/unifiedsearch/{self.query}')
        lol = b.find_elements_by_xpath("//html")
        for t in lol:
            info = t.text
            p = self.parse_breach(info.replace('"',"").replace("[","").replace("Breaches:","").replace("Names",""))
            l = p.split(",")
            for line in l:
                if "Name" in line:
                    self.breaches.append(line.replace("Name", "").replace(":", ""))

    def check_email_rep(self):
        headers = {
            "Key": self.emailrepkey,
            "User-Agent": "Tor"
        }
        r = requests.get(f"https://emailrep.io/{self.query}", headers=headers)
        self.emailrep = r.text.replace(" ", "").replace("\n", "").strip('":"{,}').replace('"', "").replace("}", "").replace("[", "").replace("]", "").replace("{", "").split(",")

    def ip_to_addr(self):
        b = webdriver.Chrome()
        b.get(f"https://thatsthem.com/ip/{self.query}")
        tmp = b.page_source.split(">")
        for line in tmp:
            if '<span itemprop="telephone">' in line:
                print(line)

    def results(self):
        results = {
            "passwords": self.passwords,
            "breaches": self.breaches,
            "emailrep": self.emailrep
        }
        return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search', methods=['POST'])
def search():
    username = request.form['username']
    lookup_type = request.form['lookup_type']
    
    if not username or not lookup_type:
        return jsonify({"error": "Missing username or lookup type"})

    info = Info(username, lookup_type)
    info.lookup()
    result = info.results()

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
