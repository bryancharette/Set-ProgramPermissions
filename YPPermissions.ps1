#Pull Company OU from pathname

$yPrograms=GET-CHILDITEM -Force "\\unc\programpathname"
foreach ($pathname in $yPrograms) {
$OU="ASP1\" + $pathname.name
$fullpath=$pathname.fullname


#Set required variables

$SYSTEM = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$DA = New-Object System.Security.AccessControl.FileSystemAccessRule("ASP1\Domain Admins","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$yFileMgr = New-Object System.Security.AccessControl.FileSystemAccessRule("ASP1\yFileMgr","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$yASP = New-Object System.Security.AccessControl.FileSystemAccessRule("ASP1\yASP","FullControl","ContainerInherit, ObjectInherit","None","Allow")
$Company = New-Object System.Security.AccessControl.FileSystemAccessRule($OU,"FullControl","ContainerInherit, ObjectInherit","None","Allow")
$ASPDeny = New-Object System.Security.AccessControl.FileSystemAccessRule("ASP1\All_asp_users","Write","ContainerInherit, ObjectInherit","None","Deny")
$ASPAllow = New-Object System.Security.AccessControl.FileSystemAccessRule("ASP1\All_asp_users","ReadAndExecute","ContainerInherit, ObjectInherit","None","Allow")


#Set generic permissions based on folder name and specific folder permissions per client

IF ($OU -notlike "*Yardi*")
{
$ACL = GET-ACL -PATH $fullpath
FOREACH ($USRClear in $ACL.access)
{
  $ACL.RemoveAccessRule($USRClear)
}
  $ACL.AddAccessRule($SYSTEM)
  $ACL.AddAccessRule($DA)
  $ACL.AddAccessRule($yFileMgr)
  $ACL.AddAccessRule($yASP)
echo $Company
  $ACL.AddAccessRule($Company)
  $ACL.SetAccessRuleProtection($True, $True)
SET-ACL -PATH $fullpath -AclObject $ACL
GET-CHILDITEM -Recurse -Force $fullpath | SET-ACL -AclObject $ACL
}
ELSE
{
$ACL = GET-ACL -PATH $fullpath
FOREACH ($USRClear in $ACL.access)
{
  $ACL.RemoveAccessRule($USRClear)
}
  $ACL.AddAccessRule($SYSTEM)
  $ACL.AddAccessRule($DA)
  $ACL.AddAccessRule($yFileMgr)
  $ACL.AddAccessRule($yASP)
  $ACL.AddAccessRule($ASPDeny)
  $ACL.AddAccessRule($ASPAllow)
  $ACL.SetAccessRuleProtection($True, $True)
SET-ACL -PATH $fullpath -AclObject $ACL
GET-CHILDITEM -Recurse -Force $fullpath | SET-ACL -AclObject $ACL
}
}
