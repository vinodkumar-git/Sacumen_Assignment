# Sacumen_Assignment
“Antivirus is generating system logs with the following format.

SAC:0|Sacumen|CAAS|2021.2.0|3|MALICIOUS|High|cat=C2 cs1Label=subcat cs1=DNS_TUNNELING cs2Label=vueUrls cs2=https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650 cs3Label=Tags cs3=USA,Finance cs4Label=Url cs4=https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323 cn1Label=severityScore cn1=900 msg=Malicious activity was reported in CAAS\= A threat intelligence rule has been automatically created in DAAS. dhost=bad.com dst=1.1.1.1
program to take the above string as an input and provide the following output as a dictionary
{
    cat: C2,
    cs1Labelsubcat,
    cs1: DNS_TUNNELING,
    cs2Label: vueUrls,
    cs2: https://aws-dev.sacdev.io/alerts?filter=alertId%3D%3D81650,
    cs3Label: Tags,
    cs3: USA,Finance,
    cs4Label: Url,
    cs4: https://aws-dev.sacdev.io/settings/tir?rules.sort=4%3A1&filter=state%3D%3D2&selected=9739323,
    cn1Label: severityScore,
    cn1: 900,
    msg: Malicious activity was reported in CAAS\=  A threat intelligence rule has been automatically created in DAAS.,
    dhost: bad.com,
    dst: 1.1.1.1
}
---------------------------------------------------------------------------------------------------------------------------------
NOTE: Please follow the below instructions:

The module should be developed in pure python, no frameworks should be used.
The module can have other python libraries to make it work, but those libraries references should be present in the requirements file along with the code. 
The module can be developed with OOPs or a functional programming approach.
The module must have unit test cases written with pytest and they need to have at least 85% code coverage.
There should be code documentation present for each function and file used.
There needs to be a README file documenting the details about the module, installation, and running guidelines.
The module should be installable in a virtual environment, so there should be a way to generate a wheel file.
------------------------------------------------------------------------------------------------------------------------------------
REQUIREMENTS:

1. Need VS Code Editor.
2. Python installed.
---------------------------------------------------------

ASSIGNMENT DETAILS:

1. completely based on python.
2. Have not used any libraries or framework.
------------------------------------------------------------------------------------
HOW TO DEPLOY?

1. Open folder in VS Code editor.
2. Just Run sacument_assignment.py file.
-------------------------------------------------------------------------------------

THANK YOU.
