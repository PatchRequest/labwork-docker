#!/usr/bin/python3
#
# License: CC-0

import sys
import json
import requests
from labwork03 import handle_pkcs7_padding
from labwork01 import handle_histogram,handle_caesar_cipher
from labwork02 import handle_password_keyspace,handle_mul_gf2_128,handle_block_cipher
from labwork04 import handle_gcm_mul_gf2_128,handle_gcm_block_to_poly,handle_cbc_key_equals_iv
if len(sys.argv) != 4:
	print("syntax: %s [API endpoint URI] [client ID] [assignment_name]" % (sys.argv[0]))
	sys.exit(1)

api_endpoint = sys.argv[1]
client_id = sys.argv[2]
assignment_name = sys.argv[3]

# Example handler for the "strcat" assignment
def handle_strcat(assignment):
	return " ".join(assignment["parts"])

# Example handler for "foobar" assignment
def handle_foobar(assignment):
	return { "foo": "bar" }
 

session = requests.Session()
# Get the assignment
result = session.get(api_endpoint + "/assignment/" + client_id + "/" + assignment_name)
assert(result.status_code == 200)

# See if we can compute the answer
assignment = result.json()
known_assignment_count = 0
unknown_assignment_count = 0
pass_count = 0
for testcase in assignment["testcases"]:
	if testcase["type"] == "strcat":
		known_assignment_count += 1
		response = handle_strcat(testcase["assignment"])
	elif testcase["type"] == "foobar":
		known_assignment_count += 1
		response = handle_foobar(testcase["assignment"])
	elif testcase["type"] == "histogram":
		known_assignment_count += 1
		response = handle_histogram(testcase["assignment"])
	elif testcase["type"] == "caesar_cipher":
		known_assignment_count += 1
		response = handle_caesar_cipher(testcase["assignment"])
	elif testcase["type"] == "password_keyspace":
		known_assignment_count += 1
		response = handle_password_keyspace(testcase["assignment"])
	elif testcase["type"] == "mul_gf2_128":
		known_assignment_count += 1
		response = handle_mul_gf2_128(testcase["assignment"])
	elif testcase["type"] == "block_cipher":
		known_assignment_count += 1
		response = handle_block_cipher(testcase["assignment"])
	elif testcase["type"] == "pkcs7_padding":
		known_assignment_count += 1
		response = handle_pkcs7_padding(testcase["assignment"])
	elif testcase["type"] == "gcm_block_to_poly":
		known_assignment_count += 1
		response = handle_gcm_block_to_poly(testcase["assignment"])
	elif testcase["type"] == "gcm_mul_gf2_128":
		known_assignment_count += 1
		response = handle_gcm_mul_gf2_128(testcase["assignment"])
	elif testcase["type"] == "cbc_key_equals_iv":
		known_assignment_count += 1
		response = handle_cbc_key_equals_iv(testcase["assignment"])
	else:
		unknown_assignment_count += 1
		print("Do not know how to handle type: %s" % (testcase["type"]))
		print()
		continue


	# We think we have an answer for this one, try to submit it
	result = session.post(api_endpoint + "/submission/" + testcase["tcid"], headers = {
		"Content-Type": "application/json",
	}, data = json.dumps(response))

	submission_result = result.json()
	print("Testcase %s: %s" % (testcase["tcid"], submission_result.get("status", "unknown")))
	assert(result.status_code == 200)


	
	if submission_result["status"] == "pass":
		
		pass_count += 1
print("%d known assignments, %d unknown." % (known_assignment_count, unknown_assignment_count))
print("Passed: %d. Failed: %d" % (pass_count, known_assignment_count - pass_count))
if unknown_assignment_count == 0 and known_assignment_count - pass_count == 0:
	print("All tests passed!")