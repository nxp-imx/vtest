# SPDX-License-Identifier: BSD-3-Clause

# Output stats for v2xsehsm & ecdsa operations

# Copyright 2019-2020 NXP

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
#   Neither the name of the copyright holder nor the names of its contributors
#   may be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON  ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT  (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS  SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import re

firstLogTimestamp = 0
lastLogTimestamp = 0
lineNumber = 0

totalLayerTime = 0
totalSeLayerTime = 0
seLayerTotalTimes = dict()
seLayerApiTimes = dict()
seLayerHsmTimes = dict()
seLayerSystemTimes = dict()
totalEcdsaLayerTime = 0
ecdsaLayerTotalTimes = dict()
ecdsaLayerApiTimes = dict()
ecdsaLayerBackgroundTimes = dict()
ecdsaLayerHsmTimes = dict()

hsmCallTimes = dict()
totalHsmCallTime = 0

systemCallTimes = dict()
totalSystemCallTime = 0

totalSeApiTime = 0
seApiEntryTimestamp = 0
seApiEntryFn = 0
totalSeHsmTime = 0
seHsmCallTimestamp = 0
seHsmCallFn = 0
totalSeSystemTime = 0
seSystemCallTimestamp = 0
seSystemCallFn = 0

totalEcdsaApiTime = 0
ecdsaApiEntryTimestamp = 0
ecdsaApiEntryFn = 0
totalEcdsaBackgroundTime = 0
ecdsaBackgroundEntryTimestamp = 0
ecdsaBackgroundEntryFn = 0
totalEcdsaHsmTime = 0
ecdsaHsmCallTimestamp = 0
ecdsaHsmCallFn = 0

seFunctionMaxLatencies = dict()
seFunctionMinLatencies = dict()

ecdsaFunctionLatencyStartTime = 0
ecdsaFunctionLatencyEndTime = 0
ecdsaFunctionMaxLatencies = dict()
ecdsaFunctionMinLatencies = dict()

hsmFunctionMaxLatencies = dict()
hsmFunctionMinLatencies = dict()


seFunctionNameDictionary = {
	int(0x0101) : "v2xSe_connect",
	int(0x0102) : "v2xSe_activate",
	int(0x0103) : "v2xSe_activateWithSecurityLevel",
	int(0x0104) : "v2xSe_reset",
	int(0x0105) : "v2xSe_deactivate",
	int(0x0106) : "v2xSe_disconnect",
	int(0x0107) : "v2xSe_generateMaEccKeyPair",
	int(0x0108) : "v2xSe_getMaEccPublicKey",
	int(0x0109) : "v2xSe_createMaSign",
	int(0x010A) : "v2xSe_generateRtEccKeyPair",
	int(0x010B) : "v2xSe_deleteRtEccPrivateKey",
	int(0x010C) : "v2xSe_getRtEccPublicKey",
	int(0x010D) : "v2xSe_createRtSignLowLatency",
	int(0x010E) : "v2xSe_createRtSign",
	int(0x010F) : "v2xSe_generateBaEccKeyPair",
	int(0x0110) : "v2xSe_deleteBaEccPrivateKey",
	int(0x0111) : "v2xSe_getBaEccPublicKey",
	int(0x0112) : "v2xSe_createBaSign",
	int(0x0113) : "v2xSe_deriveRtEccKeyPair",
	int(0x0114) : "v2xSe_activateRtKeyForSigning",
	int(0x0115) : "v2xSe_getAppletVersion",
	int(0x0116) : "v2xSe_getRandomNumber",
	int(0x0117) : "v2xSe_getSeInfo",
	int(0x0118) : "v2xSe_getCryptoLibVersion",
	int(0x0119) : "v2xSe_getPlatformInfo",
	int(0x011A) : "v2xSe_getPlatformConfig",
	int(0x011B) : "v2xSe_getChipInfo",
	int(0x011C) : "v2xSe_getAttackLog",
	int(0x011D) : "v2xSe_encryptUsingEcies",
	int(0x011E) : "v2xSe_decryptUsingRtEcies",
	int(0x011F) : "v2xSe_decryptUsingMaEcies",
	int(0x0120) : "v2xSe_decryptUsingBaEcies",
	int(0x0121) : "v2xSe_getKeyLenFromCurveID",
	int(0x0122) : "v2xSe_getSigLenFromHashLen",
	int(0x0123) : "v2xSe_sendReceive",
	int(0x0124) : "v2xSe_storeData",
	int(0x0125) : "v2xSe_getData",
	int(0x0126) : "v2xSe_deleteData",
	int(0x0127) : "v2xSe_invokeGarbageCollector",
	int(0x0128) : "v2xSe_getRemainingNvm",
	int(0x0129) : "v2xSe_endKeyInjection",
	int(0x012A) : "v2xSe_getSePhase",
	int(0x012B) : "v2xSe_getKekPublicKey",
	int(0x012C) : "v2xSe_injectMaEccPrivateKey",
	int(0x012D) : "v2xSe_injectRtEccPrivateKey",
	int(0x012E) : "v2xSe_injectBaEccPrivateKey",
	int(0x012F) : "v2xSe_generateRtSymmetricKey",
	int(0x0130) : "v2xSe_deleteRtSymmetricKey",
	int(0x0131) : "v2xSe_encryptUsingRtCipher",
	int(0x0132) : "v2xSe_decryptUsingRtCipher",
	int(0x0133) : "v2xSe_encryptUsingSm2Eces",
	int(0x0134) : "v2xSe_decryptUsingRtSm2Eces",
	int(0x0135) : "v2xSe_decryptUsingMaSm2Eces",
	int(0x0136) : "v2xSe_decryptUsingBaSm2Eces",
	int(0x0137) : "v2xSe_sm2_get_z",
}

ecdsaFunctionNameDictionary = {
	int(0x0101) : "ecdsa_open",
	int(0x0102) : "ecdsa_close",
	int(0x0103) : "ecdsa_get_version",
	int(0x0104) : "ecdsa_verify_signature",
	int(0x0105) : "ecdsa_verify_signature_of_message",
	int(0x0106) : "ecdsa_decompress_public_key",
	int(0x0107) : "ecdsa_reconstruct_public_key",
	int(0x0108) : "ecdsa_sha256",
	int(0x0109) : "ecdsa_sha384",
	int(0x010A) : "ecdsa_sha512",
	int(0x010B) : "ecdsa_sm3",
}

hsmFunctionNameDictionary = {
	int(0x0201) : "hsm_open_session",
	int(0x0202) : "hsm_close_session",
	int(0x0203) : "hsm_open_key_store_service",
	int(0x0204) : "hsm_close_key_store_service",
	int(0x0205) : "hsm_generate_key",
	int(0x0206) : "hsm_manage_key",
	int(0x0207) : "hsm_manage_key_group",
	int(0x0208) : "hsm_open_key_management_service",
	int(0x0209) : "hsm_butterfly_key_expansion",
	int(0x020A) : "hsm_close_key_management_service",
	int(0x020B) : "hsm_open_cipher_service",
	int(0x020C) : "hsm_cipher_one_go",
	int(0x020D) : "hsm_ecies_decryption",
	int(0x020E) : "hsm_open_signature_generation_service",
	int(0x020F) : "hsm_close_cipher_service",
	int(0x0210) : "hsm_generate_signature",
	int(0x0211) : "hsm_prepare_signature",
	int(0x0212) : "hsm_open_signature_verification_service",
	int(0x0213) : "hsm_verify_signature",
	int(0x0214) : "hsm_import_public_key",
	int(0x0215) : "hsm_close_signature_verification_service",
	int(0x0216) : "hsm_open_rng_service",
	int(0x0217) : "hsm_close_rng_service",
	int(0x0218) : "hsm_get_random",
	int(0x0219) : "hsm_open_hash_service",
	int(0x021A) : "hsm_close_hash_service",
	int(0x021B) : "hsm_hash_one_go",
	int(0x021C) : "hsm_pub_key_reconstruction",
	int(0x021D) : "hsm_pub_key_decompression",
	int(0x021E) : "hsm_close_signature_generation_service",
	int(0x021F) : "hsm_ecies_encryption",
	int(0x0220) : "hsm_pub_key_recovery",
	int(0x0221) : "hsm_export_root_key_encryption_key",
	int(0x0222) : "hsm_open_sm2_eces_service",
	int(0x0223) : "hsm_close_sm2_eces_service",
	int(0x0224) : "hsm_sm2_eces_encryption",
	int(0x0225) : "hsm_sm2_eces_decryption",
}

systemFunctionNameDictionary = {
	int(0x0301) : "open",
	int(0x0302) : "read",
	int(0x0303) : "write",
	int(0x0304) : "close",
	int(0x0305) : "fstat",
	int(0x0306) : "remove",
	int(0x0307) : "opendir",
	int(0x0308) : "readdir",
	int(0x0309) : "closedir",
	int(0x030A) : "mkdir",
}

def extract_timestamp_ns(line):
	# Hours
	logtime = int(line[1:3])
	# Minutes
	logtime = logtime*60 + int(line[4:6])
	# Seconds
	logtime = logtime*60 + int(line[7:9])
	# Nanoseconds
	logtime = logtime*1000000000 + int(line[10:19])
	return logtime

def extract_tracepoint_type(line):
	if line.find("v2xsehsm:apiEntry") != -1:
		return "v2xsehsm:apiEntry"
	if line.find("v2xsehsm:apiExit") != -1:
		return "v2xsehsm:apiExit"
	if line.find("v2xsehsm:hsmCall") != -1:
		return "v2xsehsm:hsmCall"
	if line.find("v2xsehsm:hsmReturn") != -1:
		return "v2xsehsm:hsmReturn"
	if line.find("v2xsehsm:systemCall") != -1:
		return "v2xsehsm:systemCall"
	if line.find("v2xsehsm:systemReturn") != -1:
		return "v2xsehsm:systemReturn"
	if line.find("ecdsa:apiEntry") != -1:
		return "ecdsa:apiEntry"
	if line.find("ecdsa:apiExit") != -1:
		return "ecdsa:apiExit"
	if line.find("ecdsa:hsmCall") != -1:
		return "ecdsa:hsmCall"
	if line.find("ecdsa:hsmReturn") != -1:
		return "ecdsa:hsmReturn"
	if line.find("ecdsa:startBackgroundProcessing") != -1:
		return "ecdsa:startBackgroundProcessing"
	if line.find("ecdsa:endBackgroundProcessing") != -1:
		return "ecdsa:endBackgroundProcessing"
	return "unknown"

def extract_tracepoint_fn(line):
	field = re.search("apiFunctionID = [0-9]*", line)
	if field == None:
		return 0;
	return int(field.group()[16:])

def process_line(line):
	global firstLogTimestamp
	global lastLogTimestamp
	global lineNumber

	global totalLayerTime
	global totalSeLayerTime
	global totalEcdsaLayerTime

	global totalSeApiTime
	global seApiEntryTimestamp
	global seApiEntryFn
	global totalSeHsmTime
	global seHsmCallTimestamp
	global seHsmCallFn
	global totalSeSystemTime
	global seSystemCallTimestamp
	global seSystemCallFn
	global totalEcdsaApiTime
	global ecdsaApiEntryTimestamp
	global ecdsaApiEntryFn
	global totalEcdsaBackgroundTime
	global ecdsaBackgroundEntryTimestamp
	global ecdsaBackgroundEntryFn
	global totalEcdsaHsmTime
	global ecdsaHsmCallTimestamp
	global ecdsaHsmCallFn

	global totalHsmCallTime

	global totalSystemCallTime

	global ecdsaFunctionLatencyStartTime
	global ecdsaFunctionLatencyEndTime
	global ecdsaFunctionLatencyIndex

	timestamp = extract_timestamp_ns(line)
	tracetype = extract_tracepoint_type(line)
	tracefn = extract_tracepoint_fn(line)

	if tracetype == "v2xsehsm:apiEntry":
		if seApiEntryTimestamp != 0:
			print("WARNING: mismatch of v2xsehsm:apiEntry field on line " + str(lineNumber))
		seApiEntryTimestamp = timestamp
		seApiEntryFn = tracefn
	elif tracetype == "v2xsehsm:apiExit":
		if seApiEntryTimestamp == 0:
			print("WARNING: mismatch of v2xsehsm:apiExit field on line " + str(lineNumber))
		elif seApiEntryFn != tracefn:
			print("WARNING: mismatch of v2xsehsm:apiExit function on line " + str(lineNumber))
		else:
			difftime = timestamp - seApiEntryTimestamp
			seApiEntryTimestamp = 0
			totalSeApiTime += difftime
			totalLayerTime += difftime
			totalSeLayerTime += difftime
			seLayerTotalTimes[tracefn] += difftime
			seLayerApiTimes[tracefn] += difftime
			if seFunctionMaxLatencies[tracefn] == -1:
				seFunctionMaxLatencies[tracefn] = difftime
				seFunctionMinLatencies[tracefn] = difftime
			else:
				if difftime > seFunctionMaxLatencies[tracefn]:
					seFunctionMaxLatencies[tracefn] = difftime
				if difftime < seFunctionMinLatencies[tracefn]:
					seFunctionMinLatencies[tracefn] = difftime
	elif tracetype == "v2xsehsm:hsmCall":
		if seHsmCallTimestamp != 0:
			print("WARNING: mismatch of v2xsehsm:hsmCall field on line " + str(lineNumber))
		seHsmCallTimestamp = timestamp
		seHsmCallFn = tracefn
	elif tracetype == "v2xsehsm:hsmReturn":
		if seHsmCallTimestamp == 0:
			print("WARNING: mismatch of v2xsehsm:hsmReturn field on line " + str(lineNumber))
		elif seHsmCallFn != tracefn:
			print("WARNING: mismatch of v2xsehsm:hsmReturn function on line " + str(lineNumber))
		else:
			difftime = timestamp - seHsmCallTimestamp
			seHsmCallTimestamp = 0
			totalSeHsmTime += difftime
			# Do not add to total layer times - its a subtask of API processing
			seLayerHsmTimes[seApiEntryFn] += difftime
			hsmCallTimes[tracefn] += difftime
			totalHsmCallTime += difftime
			if hsmFunctionMaxLatencies[tracefn] == -1:
				hsmFunctionMaxLatencies[tracefn] = difftime
				hsmFunctionMinLatencies[tracefn] = difftime
			else:
				if difftime > hsmFunctionMaxLatencies[tracefn]:
					hsmFunctionMaxLatencies[tracefn] = difftime
				if difftime < hsmFunctionMinLatencies[tracefn]:
					hsmFunctionMinLatencies[tracefn] = difftime
	elif tracetype == "v2xsehsm:systemCall":
		if seSystemCallTimestamp != 0:
			print("WARNING: mismatch of v2xsehsm:systemCall field on line " + str(lineNumber))
		seSystemCallTimestamp = timestamp
		seSystemCallFn = tracefn
	elif tracetype == "v2xsehsm:systemReturn":
		if seSystemCallTimestamp == 0:
			print("WARNING: mismatch of v2xsehsm:systemReturn field on line " + str(lineNumber))
		elif seSystemCallFn != tracefn:
			print("WARNING: mismatch of v2xsehsm:systemReturn function on line " + str(lineNumber))
		else:
			difftime = timestamp - seSystemCallTimestamp
			seSystemCallTimestamp = 0
			totalSeSystemTime += difftime
			# Do not add to total layer times - its a subtask of API processing
			seLayerSystemTimes[seApiEntryFn] += difftime
			systemCallTimes[tracefn] += difftime
			totalSystemCallTime += difftime
	elif tracetype == "ecdsa:apiEntry":
		if ecdsaFunctionLatencyStartTime != 0:
			latency = ecdsaFunctionLatencyEndTime - ecdsaFunctionLatencyStartTime
			if ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] == -1:
				ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] = latency
				ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex] = latency
			else:
				if latency > ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex]:
					ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] = latency
				if latency < ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex]:
					ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex] = latency
		ecdsaFunctionLatencyStartTime = timestamp
		ecdsaFunctionLatencyIndex = tracefn
		if ecdsaApiEntryTimestamp != 0:
			print("WARNING: mismatch of ecdsa:apiEntry field on line " + str(lineNumber))
		ecdsaApiEntryTimestamp = timestamp
		ecdsaApiEntryFn = tracefn
	elif tracetype == "ecdsa:apiExit":
		if ecdsaApiEntryTimestamp == 0:
			print("WARNING: mismatch of ecdsa:apiExit field on line " + str(lineNumber))
		elif ecdsaApiEntryFn != tracefn:
			print("WARNING: mismatch of ecdsa:apiExit function on line " + str(lineNumber))
		else:
			difftime = timestamp - ecdsaApiEntryTimestamp
			ecdsaApiEntryTimestamp = 0
			totalEcdsaApiTime += difftime
			totalLayerTime += difftime
			totalEcdsaLayerTime += difftime
			ecdsaLayerTotalTimes[tracefn] += difftime
			ecdsaLayerApiTimes[tracefn] += difftime
			ecdsaFunctionLatencyEndTime = timestamp
	elif tracetype == "ecdsa:hsmCall":
		if ecdsaHsmCallTimestamp != 0:
			print("WARNING: mismatch of ecdsa:hsmCall field on line " + str(lineNumber))
		ecdsaHsmCallTimestamp = timestamp
		ecdsaHsmCallFn = tracefn
	elif tracetype == "ecdsa:hsmReturn":
		if ecdsaHsmCallTimestamp == 0:
			print("WARNING: mismatch of ecdsa:hsmReturn field on line " + str(lineNumber))
		elif ecdsaHsmCallFn != tracefn:
			print("WARNING: mismatch of ecdsa:hsmReturn function on line " + str(lineNumber))
		else:
			difftime = timestamp - ecdsaHsmCallTimestamp
			ecdsaHsmCallTimestamp = 0
			totalEcdsaHsmTime += difftime
			# Do not add to total layer times - its a subtask of background processing
			ecdsaLayerHsmTimes[ecdsaApiEntryFn] += difftime
			hsmCallTimes[tracefn] += difftime
			totalHsmCallTime += difftime
			if hsmFunctionMaxLatencies[tracefn] == -1:
				hsmFunctionMaxLatencies[tracefn] = difftime
				hsmFunctionMinLatencies[tracefn] = difftime
			else:
				if difftime > hsmFunctionMaxLatencies[tracefn]:
					hsmFunctionMaxLatencies[tracefn] = difftime
				if difftime < hsmFunctionMinLatencies[tracefn]:
					hsmFunctionMinLatencies[tracefn] = difftime
	elif tracetype == "ecdsa:startBackgroundProcessing":
		if ecdsaBackgroundEntryTimestamp != 0:
			print("WARNING: mismatch of ecdsa:startBackgroundProcessing field on line " + str(lineNumber))
		ecdsaBackgroundEntryTimestamp = timestamp
		ecdsaBackgroundEntryFn = tracefn
	elif tracetype == "ecdsa:endBackgroundProcessing":
		if ecdsaBackgroundEntryTimestamp == 0:
			print("WARNING: mismatch of ecdsa:endBackgroundProcessing field on line " + str(lineNumber))
		elif ecdsaBackgroundEntryFn != tracefn:
			print("WARNING: mismatch of ecdsa:endBackgroundProcessing function on line " + str(lineNumber))
		else:
			difftime = timestamp - ecdsaBackgroundEntryTimestamp
			ecdsaBackgroundEntryTimestamp = 0
			totalEcdsaBackgroundTime += difftime
			totalLayerTime += difftime
			totalEcdsaLayerTime += difftime
			ecdsaLayerTotalTimes[ecdsaApiEntryFn] += difftime
			ecdsaLayerBackgroundTimes[ecdsaApiEntryFn] += difftime
			ecdsaFunctionLatencyEndTime = timestamp
	else:
		print("WARNING: unknown trace entry on line " + str(lineNumber))

	if firstLogTimestamp == 0:
		firstLogTimestamp = timestamp
	lastLogTimestamp = timestamp

# ================  ENTRY  =========================

if len(sys.argv) != 2:
    print("USAGE: " + sys.argv[0] + " <inputfile>")
    exit()

tracefile = open(sys.argv[1])

for entry in seFunctionNameDictionary:
	seLayerTotalTimes[entry] = 0
	seLayerApiTimes[entry] = 0
	seLayerHsmTimes[entry] = 0
	seLayerSystemTimes[entry] = 0
	seFunctionMaxLatencies[entry] = -1
	seFunctionMinLatencies[entry] = -1
for entry in ecdsaFunctionNameDictionary:
	ecdsaLayerTotalTimes[entry] = 0
	ecdsaLayerApiTimes[entry] = 0
	ecdsaLayerBackgroundTimes[entry] = 0
	ecdsaLayerHsmTimes[entry] = 0
	ecdsaFunctionMaxLatencies[entry] = -1
	ecdsaFunctionMinLatencies[entry] = -1
for entry in hsmFunctionNameDictionary:
	hsmCallTimes[entry] = 0
	hsmFunctionMaxLatencies[entry] = -1
	hsmFunctionMinLatencies[entry] = -1
for entry in systemFunctionNameDictionary:
	systemCallTimes[entry] = 0


while True:
	line = tracefile.readline()
	lineNumber += 1
	if not line:
		break
	if line[0] != '[':
		continue
	process_line(line)



if ecdsaApiEntryTimestamp != 0:
	print("WARNING: missing ecdsa:apiExit field at end of file")
if seApiEntryTimestamp != 0:
	print("WARNING: missing se:apiExit field at end of file")
if ecdsaFunctionLatencyStartTime != 0:
	latency = ecdsaFunctionLatencyEndTime - ecdsaFunctionLatencyStartTime
	if ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] == -1:
		ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] = latency
		ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex] = latency
	else:
		if latency > ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex]:
			ecdsaFunctionMaxLatencies[ecdsaFunctionLatencyIndex] = latency
		if latency < ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex]:
			ecdsaFunctionMinLatencies[ecdsaFunctionLatencyIndex] = latency

print("Total layer time: " +
	str(totalLayerTime) +
	" ns")

if totalSeLayerTime != 0:
	print(" - se time: " +
		str(totalSeLayerTime) +
		" ns, " +
		"{0:3.2f}".format(totalSeLayerTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in API: " +
		str(totalSeApiTime) +
		" ns, " +
		"{0:3.2f}".format(totalSeApiTime * 100
				/ totalSeLayerTime) +
		"% of se, " +
		"{0:3.2f}".format(totalSeApiTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in HSM: " +
		str(totalSeHsmTime) +
		" ns, " +
		"{0:3.2f}".format(totalSeHsmTime * 100
				/ totalSeLayerTime) +
		"% of se, " +
		"{0:3.2f}".format(totalSeHsmTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in system: " +
		str(totalSeSystemTime) +
		" ns, " +
		"{0:3.2f}".format(totalSeSystemTime * 100
				/ totalSeLayerTime) +
		"% of se, " +
		"{0:3.2f}".format(totalSeSystemTime * 100
				/ totalLayerTime) +
		"% of total")
else:
	print(" - se time: 0 ns")

if totalEcdsaLayerTime != 0:
	print(" - ecdsa time: " +
		str(totalEcdsaLayerTime) +
		" ns, " +
		"{0:3.2f}".format(totalEcdsaLayerTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in API: " +
		str(totalEcdsaApiTime) +
		" ns, " +
		"{0:3.2f}".format(totalEcdsaApiTime * 100
				/ totalEcdsaLayerTime) +
		"% of ecdsa, " +
		"{0:3.2f}".format(totalEcdsaApiTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in background: " +
		str(totalEcdsaBackgroundTime) +
		" ns, " +
		"{0:3.2f}".format(totalEcdsaBackgroundTime * 100
				/ totalEcdsaLayerTime) +
		"% of ecdsa, " +
		"{0:3.2f}".format(totalEcdsaBackgroundTime * 100
				/ totalLayerTime) +
		"% of total")
	print("   - time in HSM: " +
		str(totalEcdsaHsmTime) +
		" ns, " +
		"{0:3.2f}".format(totalEcdsaHsmTime * 100
				/ totalEcdsaLayerTime) +
		"% of ecdsa, " +
		"{0:3.2f}".format(totalEcdsaHsmTime * 100
				/ totalLayerTime) +
		"% of total")
else:
	print(" - ecdsa time: 0 ns")

print("Time in layer functions:")
for entry in seFunctionNameDictionary:
	if seLayerTotalTimes[entry] != 0:
		print(seFunctionNameDictionary[entry] +
			": " +
			str(seLayerTotalTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(seLayerTotalTimes[entry] * 100
							/ totalSeLayerTime) +
			"% of se layer, " +
			"{0:3.2f}".format(seLayerTotalTimes[entry] * 100
							/ totalLayerTime) +
			"% of total")
		print(" - time in API: " +
			str(seLayerApiTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(seLayerApiTimes[entry] * 100
						/ seLayerTotalTimes[entry]) +
			"% of function, " +
			"{0:3.2f}".format(seLayerApiTimes[entry] * 100
							/ totalSeLayerTime) +
			"% of se layer")
		print(" - time in HSM: " +
			str(seLayerHsmTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(seLayerHsmTimes[entry] * 100
							/ seLayerApiTimes[entry]) +
			"% of API, " +
			"{0:3.2f}".format(seLayerHsmTimes[entry] * 100
						/ seLayerTotalTimes[entry]) +
			"% of function")
		print(" - time in system: " +
			str(seLayerSystemTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(seLayerSystemTimes[entry] * 100
							/ seLayerApiTimes[entry]) +
			"% of API, " +
			"{0:3.2f}".format(seLayerSystemTimes[entry] * 100
						/ seLayerTotalTimes[entry]) +
			"% of function")
		if seFunctionMaxLatencies[entry] != -1:
			print(" - max latency: " +
				str(seFunctionMaxLatencies[entry]) +
				" ns, " +
				str(seFunctionMaxLatencies[entry]/1000000) +
				" ms, ")
			print(" - min latency: " +
				str(seFunctionMinLatencies[entry]) +
				" ns, " +
				str(seFunctionMinLatencies[entry]/1000000) +
				" ms, ")
for entry in ecdsaFunctionNameDictionary:
	if ecdsaLayerTotalTimes[entry] != 0:
		print(ecdsaFunctionNameDictionary[entry] +
			": " +
			str(ecdsaLayerTotalTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(ecdsaLayerTotalTimes[entry] * 100
							/ totalEcdsaLayerTime) +
			"% of ecdsa layer, " +
			"{0:3.2f}".format(ecdsaLayerTotalTimes[entry] * 100
							/ totalLayerTime) +
			"% of total")
		print(" - time in API: " +
			str(ecdsaLayerApiTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(ecdsaLayerApiTimes[entry] * 100
						/ ecdsaLayerTotalTimes[entry]) +
			"% of function, " +
			"{0:3.2f}".format(ecdsaLayerApiTimes[entry] * 100
							/ totalEcdsaLayerTime) +
			"% of ecdsa layer")
		if ecdsaLayerBackgroundTimes[entry] != 0:
			print(" - time in background: " +
				str(ecdsaLayerBackgroundTimes[entry]) +
				" ns, " +
				"{0:3.2f}".format(ecdsaLayerBackgroundTimes[entry] * 100
							/ ecdsaLayerTotalTimes[entry]) +
				"% of function, " +
				"{0:3.2f}".format(ecdsaLayerBackgroundTimes[entry] * 100
								/ totalEcdsaLayerTime) +
				"% of ecdsa layer")
			if ecdsaLayerHsmTimes[entry] != 0:
				print(" - time in HSM: " +
					str(ecdsaLayerHsmTimes[entry]) +
					" ns, " +
					"{0:3.2f}".format(ecdsaLayerHsmTimes[entry] * 100
									/ ecdsaLayerBackgroundTimes[entry]) +
					"% of background, " +
					"{0:3.2f}".format(ecdsaLayerHsmTimes[entry] * 100
								/ ecdsaLayerTotalTimes[entry]) +
					"% of function")
			else:
				print(" - time in HSM: 0 ns")
		else:
			print(" - time in background: 0 ns")
			if ecdsaLayerHsmTimes[entry] != 0:
				print(" - time in HSM: " +
					str(ecdsaLayerHsmTimes[entry]) +
					" ns, " +
					"{0:3.2f}".format(ecdsaLayerHsmTimes[entry] * 100
								/ ecdsaLayerTotalTimes[entry]) +
					"% of function")
			else:
				print(" - time in HSM: 0 ns")
		if ecdsaFunctionMaxLatencies[entry] != -1:
			print(" - max latency: " +
				str(ecdsaFunctionMaxLatencies[entry]) +
				" ns, " +
				str(ecdsaFunctionMaxLatencies[entry]/1000000) +
				" ms, ")
			print(" - min latency: " +
				str(ecdsaFunctionMinLatencies[entry]) +
				" ns, " +
				str(ecdsaFunctionMinLatencies[entry]/1000000) +
				" ms, ")


print("Time in HSM functions:")
for entry in hsmFunctionNameDictionary:
	if hsmCallTimes[entry] != 0:
		print(hsmFunctionNameDictionary[entry] +
			": " +
			str(hsmCallTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(hsmCallTimes[entry] * 100
							/ totalHsmCallTime) +
			"% of hsm, " +
			"{0:3.2f}".format(hsmCallTimes[entry] * 100
							/ totalLayerTime) +
			"% of total")
		if hsmFunctionMaxLatencies[entry] != -1:
			print(" - max latency: " +
				str(hsmFunctionMaxLatencies[entry]) +
				" ns, " +
				str(hsmFunctionMaxLatencies[entry]/1000000) +
				" ms, ")
			print(" - min latency: " +
				str(hsmFunctionMinLatencies[entry]) +
				" ns, " +
				str(hsmFunctionMinLatencies[entry]/1000000) +
				" ms, ")

print("Time in system functions:")
for entry in systemFunctionNameDictionary:
	if systemCallTimes[entry] != 0:
		print(systemFunctionNameDictionary[entry] +
			": " +
			str(systemCallTimes[entry]) +
			" ns, " +
			"{0:3.2f}".format(systemCallTimes[entry] * 100
							/ totalSystemCallTime) +
			"% of system calls, " +
			"{0:3.2f}".format(systemCallTimes[entry] * 100
							/ totalLayerTime) +
			"% of total")
