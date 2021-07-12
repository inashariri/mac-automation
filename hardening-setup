#!/usr/bin/env bash

#############################
   ## Hardening Setups ##
#############################

if [ "$EUID" -ne 0 ]; then
    script_path=$([[ "$0" = /* ]] && echo "$0" || echo "$PWD/${0#./}")
    sudo "$script_path" || (
        echo 'Administrator privileges are required.'
        exit 1
    )
    exit 0
fi

LocalHomes=$(/usr/bin/dscl . -list /Users NFSHomeDirectory | grep -v /var/ | grep -v /Library/ | awk '$2 ~ /^\// {print $2;}')

for OneHome in $LocalHomes; do
    userName=$(/bin/echo $OneHome | awk -F "/" '{print $NF;}')

# ----------------------------------------------------------
# ---------------------Enable firewall----------------------
# ----------------------------------------------------------
echo '--- 1. ENABLE FIREWALL'
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
# ----------------------------------------------------------



# ----------------------------------------------------------
# ----------Disable Handoff Between Mac and Icloud----------
# ----------------------------------------------------------
echo '--- 2. DISABLE HANDOFF MAC AND ICLOUD'
sudo -u $userName defaults write $OneHome/Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist ActivityAdvertisingAllowed -bool no
sudo -u $userName defaults write $OneHome/Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist ActivityReceivingAllowed -bool no
# ----------------------------------------------------------



# ----------------------------------------------------------
# -------------------Enable Auto Updates Mac----------------
# ----------------------------------------------------------
echo '--- 3. ENABLE AUTO UPDATES'
/usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticCheckEnabled -bool true
/usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticDownload -bool true
/usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist AutomaticallyInstallMacOSUpdates -bool true
/usr/bin/defaults write /Library/Preferences/com.apple.commerce.plist AutoUpdate -bool true
/usr/bin/defaults write /Library/Preferences/com.apple.SoftwareUpdate.plist CriticalUpdateInstall -bool true
# ----------------------------------------------------------



# ----------------------------------------------------------
# --------------Enable ScreenSaver Every 5 Minutes----------
# ----------------------------------------------------------
echo '--- 4. ENABLE SCREENSAVER FOR 5 MIN'
#sudo -u ${USER_NAME[@]} defaults -currentHost write com.apple.screensaver idleTime -int 300
sudo -u $userName defaults -currentHost write com.apple.screensaver idleTime -int 300
# ----------------------------------------------------------



# ----------------------------------------------------------
# -----------------Enable Tap to Click----------------------
# ----------------------------------------------------------
echo '--- 5. ENABLE TAP TO CLICK'
#sudo -u ${USER_NAME[@]} defaults write com.apple.AppleMultitouchTrackpad Clicking -bool true
sudo -u $userName defaults write $OneHome/Library/Preferences/com.apple.AppleMultitouchTrackpad Clicking -bool true
# ----------------------------------------------------------



# ----------------------------------------------------------
# ------------Enable/Disable Ad Limit Tracking--------------
# ----------------------------------------------------------
echo '--- 6. DISABLE LIMIT AD TRACKING / AD PERSONALIZE'
#sudo -u ${USER_NAME[@]} defaults write com.apple.AdLib allowApplePersonalizedAdvertising -bool true
sudo -u $userName defaults write $OneHome/Library/Preferences/com.apple.AdLib.plist allowApplePersonalizedAdvertising -bool false
# ----------------------------------------------------------



# ----------------------------------------------------------
# ---------------Disable Share Mac Analytics----------------
# ----------------------------------------------------------
echo '--- 7. DISABLE SHARE MAC ANALYTICS'
sudo defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false
# ----------------------------------------------------------



# ----------------------------------------------------------
# ------------------Setting Date & Time---------------------
# ----------------------------------------------------------
echo '--- 8. SETTING DATE & TIME'
sudo systemsetup -settimezone Asia/Jakarta
# ----------------------------------------------------------



# ----------------------------------------------------------
# ----------------Turn On Filename Extension----------------
# ----------------------------------------------------------
echo '--- 9. TURN ON FILENAME EXTENSIONS'
sudo -u $userName defaults write $OneHome/Library/Preferences/.GlobalPreferences.plist AppleShowAllExtensions -bool true
# ----------------------------------------------------------



# ----------------------------------------------------------
# ----------------Disable Guest Account Login---------------
# ----------------------------------------------------------
#echo '--- Disable Guest Account Login'
#sudo defaults write /Library/Preferences/com.apple.loginwindow.plist GuestEnabled -bool false
# ----------------------------------------------------------



# ----------------------------------------------------------
# -----Disable Allow Guest To Connect To Shared Folders-----
# ----------------------------------------------------------
#echo '--- Disable Allow Guest To Connect To Shared Folders'
#sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist AllowGuestAccess -bool #true
# ----------------------------------------------------------



# ----------------------------------------------------------
# ----------------Security Audit Retention------------------
# ----------------------------------------------------------
echo '--- 10. SETTING AUDITING RETENTION'
sed -I.backup 's/.*expire-after.*/expire-after:60d/' /etc/security/audit_control;
# ----------------------------------------------------------



# ----------------------------------------------------------
# -----------------Check Audit Records----------------------
# ----------------------------------------------------------
echo '--- 11. CHECK AUDIT RECORDS'
sudo ls -le /etc/security/audit_control && ls -le /var/audit/
# ----------------------------------------------------------



# ----------------------------------------------------------
# ---------------------Check Hostname-----------------------
# ----------------------------------------------------------
echo '--- 12. CHECK HOSTNAME'
hostname
# ----------------------------------------------------------



# ----------------------------------------------------------
# -------------------Enable Filevault-----------------------
# ----------------------------------------------------------
echo '--- 13. ENABLE FILEVAULT'
echo '--- Please plug your charger & DONT FORGET to save your RECOVERY KEY!'
sudo fdesetup enable
# ----------------------------------------------------------




#############################
# Password Policy Settings ##
#############################

echo '--- 14. ENABLE PASSWORD POLICY'

MAX_FAILED=10                 # 10 max failed logins before locking
LOCKOUT=1                    # 1min lockout
PW_EXPIRE=90                    # 90 days password expiration
MIN_LENGTH=8                    # at least 8 chars for password
MIN_NUMERIC=1                   # at least 0 number in password
MIN_ALPHA_LOWER=1               # at least 0 lower case letter in password
MIN_UPPER_ALPHA=1               # at least 0 upper case letter in password
MIN_SPECIAL_CHAR=1             # at least 0 special character in password
# PW_HISTORY=0                   # remember last 3 passwords

exemptAccount1="ENTER_EXEMPT_ACCOUNT"          #Exempt account used for remote management. CHANGE THIS TO YOUR EXEMPT ACCOUNT



if [ $PW_EXPIRE -lt "1" ];
then
    echo "PW EXPIRE TIME CAN NOT BE 0 or less."
    exit 1
fi

for user in $(dscl . list /Users UniqueID | awk '$2 >= 500 {print $1}'); do
    if [ "$user" != "$exemptAccount1" ]; then

    #Check if current plist is installed by comparing the current variables to the new ones

    #PW_History
    # currentPwHistory=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>Does not match any of last $PW_HISTORY passwords</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    # newPwHistory="<string>Does not match any of last $PW_HISTORY passwords</string>"

    #MIN_SPECIAL_CHAR
    currentMinSpecialChar=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMinSpecialChar="<string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>"

    #MIN_UPPER_ALPHA
    currentUpperLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newUpperLimit="<string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>"

    #MIN_ALPHA_LOWER
    currentLowerLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newLowerLimit="<string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>"

    #MIN_NUMERIC
    currentNumLimit=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newNumLimit="<string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>"

    #MIN_LENGTH
    currentMinLength=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMinLength="<string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>"

    #PW_EXPIRE
    currentPwExpire=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<string>Change every $PW_EXPIRE days</string>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newPwExpire="<string>Change every $PW_EXPIRE days</string>"

    #LOCKOUT
    currentLockOut=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<integer>$LOCKOUT</integer>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newLockOut="<integer>$LOCKOUT</integer>"

    #MAX_FAILED
    currentMaxFailed=$(sudo pwpolicy -u "$user" -getaccountpolicies | grep "<integer>$MAX_FAILED</integer>" |  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' )
    newMaxFailed="<integer>$MAX_FAILED</integer>"


    isPlistNew=0

    # if [ "$currentPwHistory" == "$newPwHistory" ]; then
    #   echo "PW_History is the same"
    # else
    #   echo "PW_History is NOT the same"
    #   echo "current: $currentPwHistory"
    #   echo "new: $newPwHistory"
    #   isPlistNew=1
    # fi

    if [ "$currentMinSpecialChar" == "$newMinSpecialChar" ]; then
      echo "MIN_SPECIAL_CHAR is the same"
    else
      echo "MIN_SPECIAL_CHAR is NOT the same"
      echo "current: $currentMinSpecialChar"
      echo "new: $newMinSpecialChar"
      isPlistNew=1
    fi

    if [ "$currentUpperLimit" == "$newUpperLimit" ]; then
      echo "MIN_UPPER_ALPHA is the same"
    else
      echo "MIN_UPPER_ALPHA is NOT the same"
      echo "current: $currentUpperLimit"
      echo "new: $newUpperLimit"
      isPlistNew=1
    fi

    if [ "$currentLowerLimit" == "$newLowerLimit" ]; then
      echo "MIN_ALPHA_LOWER is the same"
    else
      echo "MIN_ALPHA_LOWER is NOT the same"
      echo "current: $currentLowerLimit"
      echo "new: $newLowerLimit"
      isPlistNew=1
    fi

    if [ "$currentNumLimit" == "$newNumLimit" ]; then
      echo "MIN_NUMERIC is the same"
    else
      echo "MIN_NUMERIC is NOT the same"
      echo "current: $currentNumLimit"
      echo "new: $newNumLimit"
      isPlistNew=1
    fi

    if [ "$currentMinLength" == "$newMinLength" ]; then
      echo "MIN_LENGTH is the same"
    else
      echo "MIN_LENGTH is NOT the same"
      echo "current: $currentMinLength"
      echo "new: $newMinLength"
      isPlistNew=1
    fi

    if [ "$currentPwExpire" == "$newPwExpire" ]; then
      echo "PW_Expire is the same"
    else
      echo "PW_Expire is NOT the same"
      echo "current: $currentPwExpire"
      echo "new: $newPwExpire"
      isPlistNew=1
    fi

    if [ "$currentLockOut" == "$newLockOut" ]; then
      echo "LOCKOUT is the same"
    else
      echo "LOCKOUT is NOT the same"
      echo "current: $currentLockOut"
      echo "new: $newLockOut"
      isPlistNew=1
    fi

    if [ "$currentMaxFailed" == "$newMaxFailed" ]; then
      echo "MAX_FAILED is the same"
    else
      echo "MAX_FAILED is NOT the same"
      echo "current: $currentMaxFailed"
      echo "new: $newMaxFailed"
      isPlistNew=1
    fi




    if [ "$isPlistNew" -eq "1" ]; then


    # Creates plist using variables above
    echo "<dict>
    <key>policyCategoryAuthentication</key>
      <array>
      <dict>
        <key>policyContent</key>
        <string>(policyAttributeFailedAuthentications &lt; policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime &gt; (policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds))</string>
        <key>policyIdentifier</key>
        <string>Authentication Lockout</string>
        <key>policyParameters</key>
      <dict>
      <key>autoEnableInSeconds</key>
      <integer>$LOCKOUT</integer>
      <key>policyAttributeMaximumFailedAuthentications</key>
      <integer>$MAX_FAILED</integer>
      </dict>
    </dict>
    </array>


    <key>policyCategoryPasswordChange</key>
      <array>
      <dict>
        <key>policyContent</key>
        <string>policyAttributeCurrentTime &gt; policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
        <key>policyIdentifier</key>
        <string>Change every $PW_EXPIRE days</string>
        <key>policyParameters</key>
        <dict>
        <key>policyAttributeExpiresEveryNDays</key>
          <integer>$PW_EXPIRE</integer>
        </dict>
      </dict>
      </array>


      <key>policyCategoryPasswordContent</key>
    <array>
      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '.{$MIN_LENGTH,}+'</string>
      <key>policyIdentifier</key>
        <string>Has at least $MIN_LENGTH characters</string>
      <key>policyParameters</key>
      <dict>
        <key>minimumLength</key>
        <integer>$MIN_LENGTH</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[0-9].*){$MIN_NUMERIC,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a number</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumNumericCharacters</key>
        <integer>$MIN_NUMERIC</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[a-z].*){$MIN_ALPHA_LOWER,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a lower case letter</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumAlphaCharactersLowerCase</key>
        <integer>$MIN_ALPHA_LOWER</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[A-Z].*){$MIN_UPPER_ALPHA,}+'</string>
      <key>policyIdentifier</key>
        <string>Has an upper case letter</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumAlphaCharacters</key>
        <integer>$MIN_UPPER_ALPHA</integer>
      </dict>
      </dict>


      <dict>
      <key>policyContent</key>
        <string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){$MIN_SPECIAL_CHAR,}+'</string>
      <key>policyIdentifier</key>
        <string>Has a special character</string>
      <key>policyParameters</key>
      <dict>
      <key>minimumSymbols</key>
        <integer>$MIN_SPECIAL_CHAR</integer>
      </dict>
      </dict>

    </array>
    </dict>" > /private/var/tmp/pwpolicy.plist #save the plist temp

    chmod 777 /private/var/tmp/pwpolicy.plist


        pwpolicy -u "$user" -clearaccountpolicies
        pwpolicy -u "$user" -setaccountpolicies /private/var/tmp/pwpolicy.plist
        fi
    fi
done

rm /private/var/tmp/pwpolicy.plist

#echo "Password policy successfully applied. Run \"sudo pwpolicy -u <user> -getaccountpolicies\" to see it."
echo "===> THE HARDENING IS DONE! <===="

echo 'Press any key to exit.'
read -n 1 -s
exit 0

done
