import base64
import sys
import json
import requests
import time
from helper import request_oracle_with_user_pass


def handle_timing_sidechannel(assignment):
    print(assignment)
    user = assignment["user"]

    cracked = False

    password = ""

    while not cracked:
        password_addon,temp = crack_one_char(user,password)
        password += password_addon
        cracked = temp
        print(user+"\t" + str(len(password)) + "\t" + password)

    print("Password cracked: " + password)
    return {"password": password}
    

def crack_one_char(user,current_passsword):
    possible = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    times = {}
    tests  = []
    results = []


    for char in possible:
        res = request_oracle_with_user_pass(user,current_passsword+char)
        if res["status"] != "auth_failure":
            return res["password"][-1],True

    for char in possible:
        for i in range(0,8):
            results.append(request_oracle_with_user_pass(user,current_passsword+char+ str(i)))

    for result in results:
        if result["password"][-2] in times:
            times[result["password"][-2]].append(result["time"])
        else:
            times[result["password"][-2]] = [result["time"]]
            
    # calculate average time for each char
    for key in times:
        times[key] = sum(times[key])/len(times[key])
    
    # sort by time
    times = sorted(times.items(), key=lambda x: x[1])
    return times[-1][0],False
