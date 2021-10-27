string = "SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1"

def process_msg(str):
    # here we will process and remove the msg from the string
    if "msg" and ". " in string:
        index_of_msg = string.index("msg")
        index_of_dot = string.index(". ")
        msg_string = string[index_of_msg : index_of_dot+1]
        updated_str = string.replace( msg_string ,"")
        return updated_str, msg_string

def str_to_list(str):
    list = []
    for element in str.split(' '):
        list.append(element) 
    return list

def listof_key_n_values(list_item):
    # segregate each key and value and return it back
    key = ""
    value = ""
    count = 0
    for i in list_item:
        if i == "=":
            break #break the for loop
        key += i 
        count += 1
    value = list_item[count+1:]
    return (key, value)

# MAIN
#to split the str from white spaces, we need to handle msg first
str_without_msg, msg = process_msg(string)  

# Now we removed the msg, convert the str into list using "" spaces.  
list = str_to_list(str_without_msg)

#Here we will append the msg back to its position
list[11] = msg

# create a list for keys and values
keys = []
values = []

for item in list:
    key, value = listof_key_n_values(item)
    # returned key and value are appended to keys and values list respectively.
    keys.append(key)
    values.append(value)

#for 1st key to be displayed only of 3 letters.
k = keys[0]
keys[0] = k[-3:]

# converting keys and values list into one dictionary.
d = dict(zip(keys,values))
# print(str(d).replace(', ',',\n '))


