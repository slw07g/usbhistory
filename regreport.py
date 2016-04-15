try:
    from _winreg import *
except Exception, e:
    print e
    print "WARNING: Could not import _winreg. Live system registry analysis cannot be done. You MUST specify a directory with registry hives."
try:
    import argparse
except Exception, e:
    print e
    
from regparser import RegParser
from datetime import *
import os
import traceback
import sys

try:
    import tabulate
    pass
except:
    print "tabulate module not found.\n OPTIONAL: Install the tabulate package (pip install tabulate) for tabular output"

liveReg = False
debug = False

def dprint(s):
    global debug
    if debug:
        print s

''' Queries given key values for a given keyPath 
    keyValueNames must be a list or tuple of strings
    Returns a list of tuples in the form: [(keyValueName, keyValueData, keyValueType),...]'''

def open_key(root, keyPath):
    global liveReg
    k = None
    if liveReg:
        k = OpenKey(root, keyPath)
    else:
        k = RegParser.openKey(root, keyPath)
    
    return k

def get_key_values(currKey, keyPath, keyValueNames):
    global liveReg
    assert(type(keyValueNames) in [list, tuple])
    ret = []
    rp = RegParser
    
    k = open_key(currKey, keyPath) if keyPath is not None else currKey
    if liveReg:
    
        for kvn in keyValueNames:
            tmp = QueryValueEx(k, kvn)
            ret.append((kvn, tmp[0], tmp[1]))
        
    else:
        for kvn in keyValueNames:
            tmp = rp.getKeyValue(k, kvn)
            ret.append((kvn, tmp[0], tmp[1]))
    return ret

'''Enumerate the subkeys of a key'''
def enum_key(key, idx):
    global liveReg
    k = None
    
    if liveReg:
        k = EnumKey(key, idx)
    
    else:
        k = RegParser.openSubkeyByIndex(key, idx).getKeyName()

    return k
    
def enum_key_value(key, idx):
    global liveReg
    v = None
    if liveReg:
        v = EnumValue(key, idx)
    else:
        v = RegParser.getKeyValueByIndex(key, idx)
    
    return v
    
def get_product_info(hiveRoot):

    def windows_prod_key(dpi):
        dpiB = bytearray(dpi)
        charset = "BCDFGHJKMPQRTVWXY2346789"
        key = bytearray([])
        i = 28
        while i >= 0:
            cur = 0
            x = 14
            while x >= 0:
                cur *= 256
                cur += dpiB[x + 52]
                dpiB[x + 52] = int(cur / 24) & 255 
                cur %= 24
                x -= 1
            key.append(ord(charset[cur]))
            i -= 1
            if (29 - i) % 6 == 0 and i >= 0:   
                i -= 1
                key.append(ord('-'))
        return key[::-1]
            
    global liveReg
    rp = RegParser
    results = []
    valueNames = ["ProductName", "CSDVersion", "CurrentVersion", "BuildLab", "RegisteredOrganization", "RegisteredOwner", "SoftwareType", "SystemRoot"]
    keyPath = "Microsoft\\Windows NT\\CurrentVersion"
    if liveReg:
        keyPath = "SOFTWARE\\" + keyPath
    
    kv = get_key_values(hiveRoot, keyPath, valueNames)
    
    for v in kv:
        results.append((v[0], v[1]))
    
    print "PRODUCT INFORMATION\n"
    try:
        print tabulate.tabulate(results, ["Attribute", "Value"], tablefmt='psql')
    except:
        for res in results:
            print res[0].ljust(28) + res[1]
            
    print "\n\n"
    
    return


def get_current_control_set(hiveRoot):
    global liveReg
    cs = None
    keyPath = "Select" 
    if liveReg:
        keyPath =  "SYSTEM\\" + keyPath
    cs = get_key_values(hiveRoot, keyPath, ["Current"])[0][1]
    
    return cs


def get_timezone_info(hiveRoot):
    global liveReg
    ret = None
    cs = get_current_control_set(hiveRoot)
    keyPath = "ControlSet%03i\\Control\\TimeZoneInformation" % cs
    if liveReg:
        keyPath = "SYSTEM\\" + keyPath
    tmp = get_key_values(hiveRoot, keyPath, ["StandardName", "DaylightName"])
    if tmp is not None:
        ret = []
        for kv in tmp:
            ret.append((kv[0], kv[1]))
    return  ret

def get_winlogon_info(hiveRoot):
    global liveRoot
    
    keyPath = "Microsoft\\Windows NT\\CurrentVersion\\WinLogon"
    if liveReg:
        keyPath = "SOFTWARE\\" + keyPath
    winlogon = open_key(hiveRoot, keyPath)
    
    valueNames = ["DefaultDomainName", "DefaultUserName", "DefaultPassword", "AltDefaultDomainName", "AltDefaultUserName", "AltDefaultPassword"]
    
    results = []
    for vn in valueNames:
        try:
            values = get_key_values(winlogon, None, [vn])
            val = values[0][1]
        except Exception, e:
            val = "** N/A **"
            #print traceback.format_exc()
        results.append((vn, val))
    
    print "WINLOGON INFO\n"
    try:
        print tabulate.tabulate(results, ["Attribute", "Value"], tablefmt='psql')
    except:
        print "\n".join([str(result) for result in results])
    
    print "\n\n"
        
        

def get_usb_history(hiveRoot):
    global liveReg
    
    keyPath = "Control\\DeviceClasses\\"
    if liveReg:
        keyPath = "SYSTEM\\CurrentControlSet\\"+ keyPath
    else:
        keyPath = "CurrentControlSet%03i\\%s" % (get_current_control_set(hiveRoot), keyPath)
        
    print keyPath
        
    usbClasses = open_key(hiveRoot, keyPath)
    
    res = []
    for i in range(1024):
        try:
            usbClassSubKey = enum_key(hiveRoot, i)
        except Exception, e:
            break
        
        for j in range(1024):
            try:
                usbClass = enum_key_value(usbClassSubKey, j)
                devInstance = get_key_values(usbClass, None, ["DeviceInstance"])
                print devInstance
            except Exception, e:
                print "Error w/ deviceInstance"
                continue
    
        
def get_system_report(hiveRoot):
    global liveReg
    

    cs = get_current_control_set(hiveRoot)
    tz = get_timezone_info(hiveRoot)

    resultsSet = [("CurrentControlSet", cs)]
    resultsSet.extend(tz)
    results = resultsSet
    
    print "SYSTEM INFORMATION\n"
    try:
        print tabulate.tabulate(results, ["Attribute", "Value"], tablefmt='psql')
    except:
        for res in results:
            print res[0].ljust(28) + str(res[1])
    print "\n\n"
    
    get_winlogon_info(hiveRoot)
    
    get_usb_history(hiveRoot)
    
    
    return None
    
    
def get_installed_programs(hiveRoot):
    global liveReg
    
    #keyPath = "Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"
    keyPath = "Microsoft\\Windows\\CurrentVersion\\Uninstall"
    if liveReg:
        keyPath = "SOFTWARE\\" + keyPath
    valueNames = ["DisplayName", "DisplayVersion", "InstallDate", "Publisher"]
    products = open_key(hiveRoot, keyPath)
    
    programs = []
    for i in range(1024):
        try:
            subkeyName = enum_key(products, i)
            #print subkeyName
            program = []
            tmp = ()
            for vn in valueNames:
                try:
                    #print subkeyName
                    val = get_key_values(open_key(hiveRoot, keyPath + "\\" +  subkeyName), None , [vn])
                    for value in val:
                        program.append(value[1])
                except:
                    entry = "--N/A"
                    if vn == "DisplayName":
                        entry += " (%s)" % subkeyName
                    
                    program.append(entry)
                    #print "ERROR: (%s)... %s " % (vn, subkeyName)
                    continue
            #program.append(tmp)
            programs.append(program)
        except:
            #print traceback.format_exc()
            continue
    
    sortedProgs = sorted(programs, key=lambda program: program[0])
    
    print "INSTALLED PROGRAMS (not including portable applications)\n"
    try:
        print tabulate.tabulate(sortedProgs, valueNames, tablefmt='psql')
    except:
        print "\n".join(str(sortedProg) for sortedProg in sortedProgs)
    
    print "\n\n"



def get_software_report(hiveRoot):
    
    get_product_info(hiveRoot)
    try:
        get_installed_programs(hiveRoot)
    except:
        print traceback.format_exc()
    
    return None
    


def get_sam_report(hiveRoot):
    # Read SAM information
    global liveReg
    namesKeyPath = "SAM\\Domains\\Account\\Users\\Names"
    headers = ["UserID", "UserName"]
    users = []
    rp = RegParser
    
    if liveReg:
        namesKeyPath = "SAM\\" + namesKeyPath
        
    try:
        namesKey = open_key(hiveRoot, namesKeyPath)
        
        for i in range(1024):
            try:
                userName = enum_key(namesKey, i)
                userNameKey = open_key(namesKey, userName)
                userID = enum_key_value(userNameKey, 0)[2]
                users.append(("0x%x" % userID, userName))
                
            except Exception, e:
                #dprint(traceback.format_exc())
                break
        
    except Exception, e:
        dprint(traceback.format_exc())
        raise Exception("Could not locate usernames in SAM hive")
    
                          
    if len(users) > 0:
        print "\n\nSAM (User) INFORMATION\n"
        try:
            print tabulate.tabulate(users, headers, tablefmt="psql")
        except:
            for u in users:
                print u[0].ljust(10) + u[1]
            pass
        
        print "\n\n"
    return users



'''Generate Summary Report from Registry Hive Artifacts'''
def get_report_offline(directory="."):
    rp = RegParser
    
    for filename in os.listdir(directory):
        
        if filename != 'SAM':
            #continue
            pass
        filepath = os.path.join(os.path.abspath(directory), filename)
        if os.path.isdir(filepath):
            continue
        print filepath
        r = None
        try:
            r = rp(filepath, "lolwut")
            hHive = r.getHiveRootKey()
        except:
            #print traceback.format_exc()
            continue
    
        
        
        for fn in [get_software_report, get_system_report, get_sam_report]:
            try:
                fn(hHive)
            except:
                dprint(traceback.format_exc())
                continue
            
        
        if r is not None:
            r.close()
        
def get_report_live():

    hHive = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    startDate = datetime(1601, 1, 1)
    
    for fn in [get_software_report, get_system_report, get_sam_report]:
        try:
            fn(hHive)
        except:
            print traceback.format_exc()
            continue
        

    

    return None

def main(winregLoaded):
    p = argparse.ArgumentParser(description="Search an offline or live system registry's USB History. Only works on NT registries")
    argGroup = p.add_mutually_exclusive_group(required=False)
    argGroup.add_argument("-d", "--hiveDir", help="Directory containing registry hives")
    argGroup.add_argument("-l", "--live", help="Search a live system registry", const=1, nargs='?')
    p.add_argument("-D", "--debug", help="Print errors and warnings", action='store_true', default=False)
    args = p.parse_args()
    global liveReg
    
    args.live = True if args.live is not True and args.hiveDir is None else args.live
    liveReg = True if args.live is not None else False
    print args.live
    print winregLoaded
    entries = None
    
    global debug
    if args.debug is True:
        debug = True
    
    try:
        print "Analyzing Live System Registry"
        if winregLoaded is True and args.live is not None:
            entries = get_report_live()
                
        else:
            print "Analyzing Registry Offline"
            entries = get_report_offline(args.hiveDir)
        if entries is not None:
            for e in entries:
                print e
    except Exception, e:
        print e
    #raw_input()

if __name__ ==  "__main__":
    winregAvailable = True
    try:
        import _winreg
    except Exception, e:
        print e
        winregAvailable = False
    main(winregAvailable)
