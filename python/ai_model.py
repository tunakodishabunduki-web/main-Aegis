#!/usr/bin/env python3
"""
ai_model.py — Aegis Local AI Deception Engine
No external API. Uses Faker + templates. pip install faker
"""
import argparse, hashlib, json, random, string, sys
from datetime import datetime, timedelta

try:
    from faker import Faker
    fake = Faker('en_US')
    FAKER = True
except ImportError:
    FAKER = False

TZ_FIRST = ["Amina","Baraka","Fatuma","Hassan","Juma","Neema","Omar","Saidi",
             "Zainab","Hamisi","Rehema","Bakari","Salma","Musa","Aisha","Ibrahim",
             "Pendo","Tumaini","Zawadi","Nasra","Rashid","Halima","Khamis","Mariam"]
TZ_LAST  = ["Mwangi","Hassan","Juma","Ali","Omar","Salim","Bakari","Khatib",
             "Abdallah","Nyerere","Makame","Issa","Rajabu","Hamad","Suleiman"]
TZ_DOMS  = ["growthhub.co.tz","cbetanzania.ac.tz","udsm.ac.tz","gmail.com",
             "isp.co.tz","data.co.tz","business.tz","marketplace.co.tz"]

TECH_STACKS = {
    "DJANGO":      {"server":"nginx/1.24.0","powered_by":None,"framework":"Django/4.2.7","language":"Python 3.11","error_format":"django","session_cookie":"sessionid","token_header":"Token"},
    "SPRING_BOOT": {"server":"Apache/2.4.57","powered_by":None,"framework":"Spring Boot/3.1.4","language":"Java 17","error_format":"java","session_cookie":"JSESSIONID","token_header":"Bearer"},
    "RAILS":       {"server":"Puma/6.3.1","powered_by":None,"framework":"Rails 7.0.8","language":"Ruby 3.2","error_format":"rails","session_cookie":"_session_id","token_header":"Bearer"},
    "NODEJS":      {"server":"nginx/1.22.1","powered_by":"Express","framework":"Express/4.18.2","language":"Node.js 20","error_format":"node","session_cookie":"connect.sid","token_header":"Bearer"},
    "ASPNET":      {"server":"Microsoft-IIS/10.0","powered_by":"ASP.NET","framework":"ASP.NET Core/7.0","language":"C# 11","error_format":"dotnet","session_cookie":"ASP.NET_SessionId","token_header":"Bearer"},
    "GOLANG":      {"server":"nginx/1.24.0","powered_by":None,"framework":"Gin/1.9.1","language":"Go 1.21","error_format":"go","session_cookie":"go_session","token_header":"Bearer"},
    "LARAVEL":     {"server":"Apache/2.4.54","powered_by":"PHP/7.4.33","framework":"Laravel/9.52","language":"PHP 7.4","error_format":"laravel","session_cookie":"laravel_session","token_header":"Bearer"},
}
TECH_MAP = {
    "PHP":["DJANGO","SPRING_BOOT","RAILS","NODEJS","ASPNET","GOLANG"],
    "PYTHON":["SPRING_BOOT","ASPNET","NODEJS","GOLANG","LARAVEL"],
    "NODE":["DJANGO","SPRING_BOOT","RAILS","ASPNET","GOLANG"],
    "JAVA":["DJANGO","RAILS","NODEJS","GOLANG","ASPNET"],
}

SYSTEM_ROLES = {
    "EDUCATION":["Student","Lecturer","Registrar","HOD","Finance Officer","IT Admin"],
    "WIFI_MANAGEMENT":["Subscriber","Network Admin","Reseller","Technician","Finance"],
    "ECOMMERCE":["Customer","Vendor","Admin","Warehouse","Delivery","Finance"],
    "AGENCY":["Admin","Account Manager","Content Creator","Client","Analyst"],
    "HEALTHCARE":["Patient","Doctor","Nurse","Receptionist","Lab Tech","Pharmacist"],
    "RESTAURANT":["Customer","Waiter","Chef","Manager","Cashier"],
    "GENERIC_BUSINESS":["Admin","Manager","Staff","Finance","Viewer"],
}
SYSTEM_EMAIL = {
    "EDUCATION":["cbetanzania.ac.tz","udsm.ac.tz","school.ac.tz"],
    "WIFI_MANAGEMENT":["isp.co.tz","wifi.local","data.co.tz"],
    "ECOMMERCE":["gmail.com","marketplace.co.tz","duka.tz"],
    "AGENCY":["growthhub.co.tz","agency.tz","gmail.com"],
    "HEALTHCARE":["hospital.co.tz","clinic.tz","gmail.com"],
    "GENERIC_BUSINESS":["company.co.tz","business.tz","gmail.com"],
}

def rname(): return f"{random.choice(TZ_FIRST)} {random.choice(TZ_LAST)}"
def rphone(): p=random.choice(["0621","0712","0754","0756"]); return f"+255{p[1:]}{random.randint(100000,999999)}"
def rdate(d=730): return (datetime.now()-timedelta(days=random.randint(0,d))).strftime("%Y-%m-%d %H:%M:%S")
def rid(): return random.randint(1,9999)

EXTRA_FIELDS = {
    "EDUCATION":  lambda i: {"student_id":f"CBE{random.randint(2020,2024)}{(i+1):03d}","program":random.choice(["BIT","BCOM","BSc CS","BBA"]),"year":random.randint(1,3),"gpa":round(random.uniform(2.0,4.0),2)},
    "WIFI_MANAGEMENT": lambda i: {"mac_address":":".join(f"{random.randint(0,255):02X}" for _ in range(6)),"package":random.choice(["5Mbps","10Mbps","20Mbps","Unlimited"]),"balance":f"TZS {random.randint(0,50000):,}"},
    "ECOMMERCE":  lambda i: {"orders_count":random.randint(0,50),"total_spent":f"TZS {random.randint(0,2000000):,}","tier":random.choice(["Bronze","Silver","Gold"])},
    "AGENCY":     lambda i: {"clients_count":random.randint(1,20),"campaigns_active":random.randint(0,10),"plan":random.choice(["Starter","Growth","Enterprise"])},
    "HEALTHCARE": lambda i: {"blood_type":random.choice(["A+","B+","O+","AB+"]),"ward":random.choice(["OPD","General","ICU","Maternity"])},
    "GENERIC_BUSINESS": lambda i: {},
}

def generate_users(system_type, count=6, skill_level="SCRIPT_KIDDIE"):
    roles   = SYSTEM_ROLES.get(system_type, SYSTEM_ROLES["GENERIC_BUSINESS"])
    domains = SYSTEM_EMAIL.get(system_type, TZ_DOMS)
    extra_fn= EXTRA_FIELDS.get(system_type, EXTRA_FIELDS["GENERIC_BUSINESS"])
    users   = []
    for i in range(count):
        fn, ln = random.choice(TZ_FIRST), random.choice(TZ_LAST)
        dom    = random.choice(domains)
        user   = {
            "id":i+1,"username":f"{fn.lower()}.{ln.lower()}","full_name":f"{fn} {ln}",
            "email":f"{fn.lower()}.{ln.lower()}@{dom}","phone":rphone(),
            "role":random.choice(roles),"is_active":random.random()>0.1,
            "created_at":rdate(),"last_login":rdate(30),
            "password_hash":hashlib.sha256(f"{fn}{ln}{i}".encode()).hexdigest(),
        }
        user.update(extra_fn(i))
        if skill_level == "ADVANCED":
            user["api_key"]    = "sk_" + hashlib.md5(str(i).encode()).hexdigest()[:24]
            user["2fa_enabled"]= random.random() > 0.5
        users.append(user)
    return users

def generate_response(endpoint, system_type, phase, skill_level, method="GET"):
    count = 8 if skill_level == "ADVANCED" else 5
    if any(x in endpoint for x in ["/user","/student","/subscriber","/patient","/client"]):
        users = generate_users(system_type, count, skill_level)
        return {"data":users,"total":len(users)+random.randint(10,500),"page":1}
    if any(x in endpoint for x in ["/login","/auth"]):
        return {"success":True,"token":hashlib.sha256(str(random.random()).encode()).hexdigest(),
                "expires_at":rdate(-1),"user":generate_users(system_type,1,skill_level)[0]}
    if method in ["POST","PUT","PATCH"]:
        return {"success":True,"id":random.randint(100,99999),"message":"Record updated successfully"}
    if method == "DELETE":
        return {"success":True,"deleted":True}
    users = generate_users(system_type, count, skill_level)
    return {"data":users,"total":len(users)+random.randint(50,2000)}

def select_fake_tech(real_tech, seed=0):
    opts   = TECH_MAP.get(real_tech.upper(), TECH_MAP["PHP"])
    random.seed(seed + 42)
    chosen = random.choice(opts)
    random.seed()
    return {"key":chosen, **TECH_STACKS[chosen]}

def fake_error(fake_tech, error_type="500"):
    ts  = datetime.now().isoformat()
    uri = "/"
    errors = {
        "django":    {"detail":"A server error occurred.","code":"server_error"},
        "java":      {"timestamp":ts,"status":500,"error":"Internal Server Error","message":"","path":uri},
        "rails":     {"status":"error","message":"We're sorry, but something went wrong."},
        "node":      {"error":"Internal Server Error","message":"An unexpected error occurred","statusCode":500},
        "dotnet":    {"type":"https://httpstatuses.com/500","title":"An error occurred.","status":500},
        "go":        {"error":"internal server error","code":500},
        "laravel":   {"message":"Server Error"},
    }
    tech   = TECH_STACKS.get(fake_tech, TECH_STACKS["DJANGO"])
    fmt    = tech.get("error_format","django")
    return errors.get(fmt, errors["django"])

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--args", default="{}")
    a = p.parse_args()
    try:
        params = json.loads(a.args)
    except Exception:
        print(json.dumps({"error":"Invalid JSON"})); sys.exit(1)

    action = params.get("action","ping")
    if   action == "ping":
        print(json.dumps({"status":"running","faker":FAKER,"model":"Aegis Local AI"}))
    elif action == "generate_users":
        users = generate_users(params.get("system_type","GENERIC_BUSINESS"),
                               int(params.get("count",6)), params.get("skill_level","SCRIPT_KIDDIE"))
        print(json.dumps({"users":users,"count":len(users)}))
    elif action == "generate_response":
        print(json.dumps(generate_response(params.get("endpoint","/api/users"),
              params.get("system_type","GENERIC_BUSINESS"), params.get("phase","RECONNAISSANCE"),
              params.get("skill_level","SCRIPT_KIDDIE"), params.get("method","GET"))))
    elif action == "fake_tech":
        print(json.dumps(select_fake_tech(params.get("real","PHP"),int(params.get("site_id",0)))))
    elif action == "fake_error":
        print(json.dumps(fake_error(params.get("fake_tech","DJANGO"),params.get("error_type","500"))))
    elif action == "status":
        print(json.dumps({"status":"running","faker":FAKER,
                          "system_types":list(SYSTEM_ROLES.keys()),"tech_options":list(TECH_STACKS.keys())}))
    else:
        print(json.dumps({"error":f"Unknown action: {action}"})); sys.exit(1)

if __name__ == "__main__":
    main()
