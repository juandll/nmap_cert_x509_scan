--[[Category: safe]]
local datetime = require "datetime"
local openssl = require("openssl")
local io = require("io")
local shortport = require "shortport"
local tls = require "tls"
local sslcert = require "sslcert"
local table = require "table"
local outlib = require "outlib"
local x509 = require("ssl.x509")
local stdnse = require("stdnse")

--local puny = require("luapun")

author = "Javier Gallego Montero & Juan Diego Llano"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end

local blacklist_file = stdnse.get_script_args('blacklist')

-- Set a default value for the blacklist file if the argument is not provided
if not blacklist_file or blacklist_file == "" then
    blacklist_file = "./blacklist.csv"  -- Set your default path here
end


local ssl_blacklist_file = stdnse.get_script_args('ssl_blacklist')

-- Set a default value for the blacklist file if the argument is not provided
if not ssl_blacklist_file or ssl_blacklist_file == "" then
    ssl_blacklist_file = "./sslblacklist.csv"  -- Set your default path here
end


local CAcert = {}  -- Table to store certificates with the "CA:TRUE" extension
local CAcertnum

local function file_exists(file)
    local f=io.open(file,"r")
    if f~=nil then io.close(f) return true else return false end
end


local function contains(table, value)
    for _, v in ipairs(table) do
        if v == value then
            return true
        end
    end
    return false
end


local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return outlib.sorted_by_key(output)
end

local function printTable(t)
    for key, value in pairs(t) do
        print(key, value)
    end
end

local function tablesAreEqual(table1, table2)
    for key, value in pairs(table1) do
        if table2[key] ~= value then
            return false
        end
    end

    for key, value in pairs(table2) do
        if table1[key] ~= value then
            return false
        end
    end

    return true
end

-- Read the blacklist from a file
--local blacklist = {}
--for line in io.lines("blacklist.csv") do
--    table.insert(blacklist, line)
--end

-- Function to check if a certificate is self-signed
local function isSelfSigned(cert)
    local subjectName = cert["Subject"]
    local issuerName = cert["Issuer"]
    return subjectName == issuerName
end

-- Function to verify the certificate's signature with the subject public key
local function verifySignature(cert, num)
    local server_cert = cert[num]
    local handle = io.popen("echo '" .. server_cert .. "' > /tmp/self.pem")
    handle:close()
    local server_cert_file = "/tmp/self.pem"
    local openssl_cmd = ("openssl verify -CAfile %s %s"):format(server_cert_file, server_cert_file)
    handle = io.popen(openssl_cmd)
    local verification = handle:read("*a")
    handle:close()
    local delete = io.popen("rm -f /tmp/self.pem")
    delete:close()
    if verification:find("/tmp/self.pem: OK", 1, true) then
        return false
    else
        return true
    end
end

local function readBlacklistFromFile(filename)
    local blacklist = {}
    for line in io.lines(filename) do
        local entry = {}
        local date_reported, name, severity = line:match("([^;]+);([^;]+);([^;]+)")
        entry.date_reported = date_reported
        entry.name = name
        entry.severity = severity
        table.insert(blacklist, entry)
    end
    return blacklist
end

-- Read blacklisted fingerprints
local function readFingerprintBlacklist(filename)
    
	local fingerprintBlacklist = {}
	for line in io.lines(filename) do
        if not line:find("^#") then
            local entry = {}
            local listing_date, fingerprint, listing_reason = line:match("([^,]+),([^,]+),([^,]+)")
            entry.listing_date = listing_date
            entry.fingerprint = fingerprint
            entry.listing_reason = listing_reason
            table.insert(fingerprintBlacklist, fingerprint)
        end
	end	
	return fingerprintBlacklist
end

-- Verify if certificate fingerprint is on blacklist
local function isFingerprintOnList(fingerpnt, blacklist)
	for _, entry in ipairs(blacklist) do
		if entry==fingerpnt:gsub("[\n\r]+$", "")then
			return true
		end 
	end
    return false
end


-- Function to check if the certificate is on the blacklist
local function isOnBlacklistSubject(cert, blacklist)
    local commonName = cert["Subject"]:match("CN%s*=%s*(%S+)")
    for _, entry in ipairs(blacklist) do
        if entry.name == commonName then
            return true
        end
    end

    return false
end
local function isOnBlacklistIssuer(cert, blacklist)
    local commonName = cert["Issuer"]:match("CN%s*=%s*(%S+)")
    for _, entry in ipairs(blacklist) do
        if entry.name == commonName then
            return true
        end
    end

    return false
end

local function checkHomograph(cert)
	local commonName = cert["Subject"]:match("CN%s*=%s*(%S+)")
    if commonName:find("xn--", 1, true) then
        return true
    else
        return false
    end
end

local function appendToBlacklist(filename, entry)
    local file, err = io.open(filename, "a")
    if not file then
        print("Error opening blacklist file:", err)
        return
    end
    -- Format the entry and write it to the file
    local line = string.format("%s;%s;%s\n", entry.date_reported, entry.name, entry.severity)
    file:write(line)

    file:close()
end

local function get_certificate_chain(host, port)

    local cmd = ("echo | openssl s_client -showcerts -connect %s:%s"):format(host.ip, port.number)
    

    local handle = io.popen(cmd)


    local certificate_chain = handle:read("*a")
 


    handle:close()
    return certificate_chain
end

-- Generate fingerprint from certificate
local function generateFingerprint(cert,num)
    local certi = cert[num]
    local create = io.popen("echo '" .. certi .. "' > /tmp/fing.pem")
    create:close()
    local cmd = ("openssl x509 -in /tmp/fing.pem -outform der | openssl sha1")
	local handle = io.popen(cmd)
	local fingerprint = handle:read("*a")
	handle:close()
    local finger = fingerprint:match("SHA1%(stdin%)=%s*(.+)")
    local delete = io.popen("rm -f /tmp/fing.pem")
    delete:close()
	return finger
end


local function extractCertificates(input)
    local certificates = {}
    local startPattern = "-----BEGIN CERTIFICATE-----"
    local endPattern = "-----END CERTIFICATE-----"

    -- Iterate through the input string and extract certificates
    local startPos, endPos = input:find(startPattern, 1, true)
    while startPos do
        endPos = input:find(endPattern, startPos, true)
        if endPos then
            local certificate = input:sub(startPos, endPos + #endPattern - 1)
            table.insert(certificates, certificate)
            startPos = input:find(startPattern, endPos)
        else
            break
        end
    end
    local parsed_certs = {}
    for _, cert_str in ipairs(certificates) do
        local cmd = "echo '" .. cert_str .. "' | openssl x509 -inform PEM -text"
        local handle = io.popen(cmd)
        local parsed_cert = handle:read("*a")
        handle:close()

        table.insert(parsed_certs, parsed_cert)
    end

    return parsed_certs, certificates
end
local function parse_certificatex(cert_data)
    local certificate = {}
    local hasCATrueExtension = false  -- Flag to indicate the presence of "CA:TRUE" extension
    
    -- Extracting version
    local version = cert_data:match("Version:%s*(%d+)")
    certificate.Version = version
    
    -- Extracting serial number
    local serial_number = cert_data:match("Serial Number:%s*([%d:a-fA-F]+)")
    certificate["Serial Number"] = serial_number
    
    -- Extracting signature algorithm
    local signature_algorithm = cert_data:match("Signature Algorithm:%s*([%w%-]+)")
    certificate["Signature Algorithm"] = signature_algorithm
    
    -- Extracting issuer
    local issuer = cert_data:match("Issuer:%s*(.-)\n")
    certificate.Issuer = issuer
    
    -- Extracting validity
    local not_before, not_after = cert_data:match("Not Before:%s*(.-)\n%s*Not After :%s*(.-)\n")
    certificate.Validity = {["Not Before"] = not_before, ["Not After"] = not_after}
    -- Extracting subject
    local subject = cert_data:match("Subject:%s*(.-)\n")
    certificate.Subject = subject
    
    -- Extracting public key info
    local public_key_info = cert_data:match("Public Key Algorithm:%s*(.-)\n")
    certificate["Subject Public Key Info"] = public_key_info
    
    -- Extracting public key algorithm and key size
    local key_algorithm = cert_data:match("Public Key Algorithm:%s*(.-)\n")
    certificate["Public Key Algorithm"] = key_algorithm or "N/A"

    -- Extracting key size
    local key_size = cert_data:match("(%d+)%s*bit")
    certificate["Key Size"] = key_size or "N/A"
    
    -- Extracting signature algorithm
    local signature_algorithm = cert_data:match("Signature Algorithm:%s*(%S+)")
    certificate["Signature Algorithm"] = signature_algorithm
    
    -- Extracting extensions data
    local extensions_data = cert_data:match("X509v3 extensions:(.-)Signature Algorithm:")
    --print("Extensions data:", extensions_data)

    if extensions_data then
        local extensions = {}
        local current_extension_name
    
        for line in extensions_data:gmatch("(.-)\n") do
            local extension_name = line:match("^%s*(.-):%s*$")  -- Remove leading and trailing spaces from extension name
            if extension_name then
                current_extension_name = extension_name
                extensions[current_extension_name] = {}  -- Initialize table for extension
            elseif current_extension_name then
                local extension_value = line:match("^%s*(.-)%s*$")  -- Remove leading and trailing spaces from extension value
                extensions[current_extension_name].value = (extensions[current_extension_name].value or "") .. extension_value .. "\n"
            end
        end
    
        certificate.Extensions = extensions
    end
    
    --if certificate.Extensions then
    --    for extension_name, extension_data in pairs(certificate.Extensions) do
    --       print("Extension:", extension_name)
    --        print("Value:", extension_data.value)
    --        print()  -- Separate each extension with an empty line
    --    end
    --end
    
    
    --print("X509v3 Basic Constraints Value:", certificate.Extensions["X509v3 Basic Constraints"])
    if certificate.Extensions then
        for extension_name, extension_data in pairs(certificate.Extensions) do
            if extension_name == "X509v3 Basic Constraints" and extension_data.value:match("CA:TRUE") then
                hasCATrueExtension = true
                break  -- No need to check other extensions once "CA:TRUE" is found
            end
        end
    end
    
    return certificate, hasCATrueExtension
end

local function verifyCA(cert,certca)
    return not(certca["Subject"]:match("CN%s*=%s*(%S+)") == cert["Issuer"]:match("CN%s*=%s*(%S+)"))
end

local function check_signature(certificates,num)
    local ca_cert = certificates[CAcertnum]
    local server_cert = certificates[num]
    local handle = io.popen("echo '" .. ca_cert .. "' > /tmp/ca.pem")
    handle = io.popen("echo '" .. server_cert .. "' > /tmp/server.pem")
    handle:close()
    local ca_cert_file = "/tmp/ca.pem"
    local server_cert_file = "/tmp/server.pem"
    local openssl_cmd = ("openssl verify -CAfile %s %s"):format(ca_cert_file, server_cert_file)
    handle = io.popen(openssl_cmd)
    local verification = handle:read("*a")
    handle:close()
    local delete = io.popen("rm -f /tmp/ca.pem")
    delete = io.popen("rm -f /tmp/server.pem")
    delete:close()
    if verification:find("/tmp/server.pem: OK", 1, true) then
        return true
    else
        return false
    end
end

local function algorithmVerify(cert)
    -- List of cryptographic algorithm identifiers
    -- local algorithm_identifiers = {
    --     "sha256WithRSAEncryption",
    --     "sha512WithRSAEncryption",
    --     "sha384WithRSAEncryption",
    --     "dsa_with_SHA256",
    --     "dsa_with_SHA384",
    --     "dsa_with_SHA512",
    --     "ecdsa-with-SHA256",
    --     "ecdsa-with-SHA384",
    --     "ecdsa-with-SHA512"
    -- }
    local sha_number = cert["Signature Algorithm"]:match("[sS][hH][aA](%d+)")
    if(sha_number ) then
        -- Convert the extracted number to a numeric value
        local sha_numeric = tonumber(sha_number)
        -- Check if the SHA number is 256 or higher
        if sha_numeric and sha_numeric >= 256 then
            return true
        else
            return false
        end


        
    else
        error("Error, Signature algorithm is not SHA",1)
        return false
    end

end

local function nameonblacklist(blacklist,san)

    for i = 1, #blacklist, 1 do
        if san:find(blacklist[i].name, 1, true) then
            return blacklist[i].name
        end
    end
    return nil
end

local function printCertInfo(num, subject,output)
    local subjectLength = 60 -- Adjust the length as needed

    local certInfo = string.format("---------------cert #%d to scan with name: %s", num, subject)
    local padding = string.rep(" ", subjectLength - #certInfo)
    
    table.insert(output,certInfo .. padding .. "---------------\n")
end


------ find vulerabilities function ------------
local function findVul(cert,host,num,certificates,certca,output)
    printCertInfo(num, cert["Subject"]:match("CN%s*=%s*(%S+)"),output)
    --print(string.format("------cert #%d to scan with name: %s------", num, cert["Subject"]:match("CN%s*=%s*(%S+)")))
    local blacklist
    --------- read blacklist_file ----------
    if file_exists(blacklist_file) then
        blacklist = readBlacklistFromFile(blacklist_file)
        -- Do further processing using the 'blacklist' data
    else
        return error("Error: Blacklist file not found.")
    end
    local fingerprintBlacklist
    -------- reed ssl_blacklist_file -------
    if file_exists(ssl_blacklist_file) then
        
        fingerprintBlacklist = readFingerprintBlacklist(ssl_blacklist_file)
        -- Do further processing using the 'blacklist' data
    else
        return error("Error: SSL_Blacklist file not found.")
    end
	--local fingerprintBlacklist = readFingerprintBlacklist("sslblacklist.csv")
    --printTable(blacklist[3])
    local vul = {}
    ----------- check if subjectName is on blakclist -------------  -- Basic function 4
    if isOnBlacklistSubject(cert, blacklist) then
        table.insert(output, string.format("Warning, Certificate Subject is on the blacklist: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
        vul.blacklist = true
    end
    ----------- check if Issuer is on blakclist -------------  -- Basic function 4

    if isOnBlacklistIssuer(cert, blacklist) then
        table.insert(output, string.format("Warning, Certificate Issuer is on the blacklist: %s", cert["Issuer"]:match("CN%s*=%s*(%S+)")))
        vul.blacklist = true
    end
    --------- check finger print of cert on ssl_blacklist----------- -- enhanced function 5
	local fingerpnt = generateFingerprint(certificates,num)
	if isFingerprintOnList(fingerpnt, fingerprintBlacklist) then
		table.insert(output, "Warning, fingerprint is blacklisted")
		vul.blfingerprint = true 
	end 
    --------- check if the cert is self-signed ----------- --Basic function 5
    if isSelfSigned(cert) then
        table.insert(output, string.format("Warning, Self-signed certificate: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
        vul.selfsigned = true
        ---------- if it is self signed, it verify the signature --------- --Basci function 5
		if verifySignature(certificates, num) then
			table.insert(output, string.format("Warning, Signature self-signed does not match: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
			vul.selfsignedsign = true
		end
    else
    --------------- verify CA of cert -------------------- -- Basic function 1
        if(certca ~= nil)then
            if verifyCA(cert,certca) then
                table.insert(output, string.format("Warning, certificate doesnt have CA as issuer: CertIssuer: %s CASubject: %s", cert["Issuer"]:match("CN%s*=%s*(%S+)"), certca["Subject"]:match("CN%s*=%s*(%S+)")))
                vul.verifyCA = true
            end
        

            -------------- check signature of CA with the cert ------------- --Basic function 1
            if check_signature(certificates,num) then
                table.insert(output, "Certificate is valid and it was signed by the CA")
            else
                table.insert(output, "Warning, certificate was not signed by the CA")
                vul.signed = true
            end
        end

    end
    -- enhanced function 6
	if checkHomograph(cert) then
		table.insert(output, string.format("Warning, Subject appears to be an homograph, certificate might belong to a malicious website, or contain punycode: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
		vul.verifyDomain = true
	end 

    ----------- Algorithm check ---------------------- --will check for RSA, DSA and ECDSA using SHA256
    --enhanced function 4
    if(algorithmVerify(cert)) then
        table.insert(output, string.format("the Signature algorithm: %s is strong", cert["Signature Algorithm"]))
    else
        table.insert(output, string.format("Warnigng, the signature algorithm: %s is weak", cert["Signature Algorithm"]))
    end
    ------------Check Key size ----------------------

    --enhanced function 3
    if(tonumber(cert["Key Size"]) < 2048)then
        table.insert(output, string.format("Warning, the key size is smaller than 2048 bits. Key size: %d", tonumber(cert["Key Size"])))
    end
		
    -----------Check the validity period -------------
    local monthAbbreviations = {
        Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
        Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12
    }
    local now = os.time()
    local monthAbbrev, day, hour, min, sec, year = cert.Validity["Not Before"]:match("(%a+)%s*(%d+)%s+(%d+):(%d+):(%d+)%s+(%d+) GMT")
    local month = monthAbbreviations[monthAbbrev]
    local dateTimeTable = {
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = tonumber(hour),
        min = tonumber(min),
        sec = tonumber(sec)
    }
    local v = os.time(dateTimeTable)
    local monthAbbrev2, day2, hour2, min2, sec2, year2 = cert.Validity["Not After"]:match("(%a+)%s*(%d+)%s+(%d+):(%d+):(%d+)%s+(%d+) GMT")
    local month2 = monthAbbreviations[monthAbbrev2]
    local dateTimeTable2 = {
        year = tonumber(year2),
        month = tonumber(month2),
        day = tonumber(day2),
        hour = tonumber(hour2),
        min = tonumber(min2),
        sec = tonumber(sec2)
    }

    local vv = os.time(dateTimeTable2)
    -------- Basic function 2
    if now < v or now > vv then
        table.insert(output, string.format("Warning, Certificate not within valid date range: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
        vul.daterange = true
    end
    local differenceInSeconds = os.difftime(vv, now)
    -- Enhanced function 2
    if differenceInSeconds <= (30 * 24 * 60 * 60) then
        table.insert(output, string.format("Warning, Certificate will expire in 1 month or less, it will expire in %s", cert.Validity["Not After"]))
        vul.shortdate = true
    end
    -- Enhanced function 2
    if differenceInSeconds > (2 * 365 * 24 * 60 * 60) then
        table.insert(output, string.format("Warning, Certificate is longer than 2 years, it will expire in %s", cert.Validity["Not After"]))
        vul.longdate = true
    end



    -- Check Subject Alternative Name
    if cert.Extensions then
        if cert.Extensions["X509v3 Subject Alternative Name"] then
            local isHostInCert = (host["name"] ~= "" or host["name"] ~= nil) and (cert.Extensions["X509v3 Subject Alternative Name"].value:find(host["name"], 1, true) ~= nil)
            local isCNInCert = cert.Extensions["X509v3 Subject Alternative Name"].value:find(cert["Subject"]:match("CN%s*=%s*(%S+)"), 1, true) ~= nil
            local isHostIPInCert = (host.ip ~= "") and (cert.Extensions["X509v3 Subject Alternative Name"].value:find(host.ip, 1, true) ~= nil)
            -- Basic function 3     
            if not(isHostInCert) then
                table.insert(output, string.format("Warning, Subject Alternative Name does not contain the hostname: %s", host["name"]))
                vul.sanhost = true
            end
            -- basic funtion 6
            if not(isHostIPInCert) then
                table.insert(output, string.format("Warning, Subject Alternative Name does not contain the hostname IP adress: %s", host.ip))
                vul.sanhost = true
            end
            -- Basic function 3
            if not(isCNInCert) then
                table.insert(output, string.format("Warning, Subject Alternative Name does not contain the CN: %s", cert["Subject"]:match("CN%s*=%s*(%S+)")))
                vul.sancn = true
            end
            -- Enhanced function 1
            local san_b = nameonblacklist(blacklist,cert.Extensions["X509v3 Subject Alternative Name"].value)
            if(san_b ~= nil) then
                table.insert(output, string.format("Warning, Any of the Subject Alternative name is on the blacklist: %s", san_b))
            end

        end
    end
    table.insert(output, "\n______ Scaned finifhed ______\n")
    return output
end


local function sever(vul)

end

action = function(host, port)
    local certi = {} 
    local output = {}

    --- get certificates-----------------
    local status, cert = sslcert.getCertificate(host, port)
    local certificate_chain= get_certificate_chain(host,port)
    local new_cert, certificates = extractCertificates(certificate_chain)
    for i, cert_data in ipairs(new_cert) do
        local certt, hasCATrueExtension = parse_certificatex(cert_data)
        certi[i] = certt
        
        if hasCATrueExtension then
            table.insert(CAcert, certt)  -- Save the certificate to CAcert table
            table.insert(output,string.format("\n---------CA CN: %s -----------------\n", certt["Subject"]:match("CN%s*=%s*(%S+)")))
            CAcertnum = i
        end
    end
    ------------------------------------
    
    ---------------------------------------------
    if certi then -- if there are any certs, execute the analisis
    
        for i=1, #certi do
            output = findVul(certi[i],host,i,certificates,certi[CAcertnum],output)
            --local severity = sever(vul) -- for later implementations on severity level depending on the vulerabilities found
        end
            
    else
        return ("Error: Unable to establish SSL connection.")
    end
    
    return output
end
