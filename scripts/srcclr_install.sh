#! /usr/bin/env sh

# SRCCLR_DOWNLOAD_URL: The download URL (default is
# https://download.sourceclear.com).

DOWNLOAD_URL=${SRCCLR_DOWNLOAD_URL:-'https://download.sourceclear.com'}
CURL_C='curl --location --show-error --connect-timeout 10 --ssl-reqd '

command_exist() {
  type "$@" &> /dev/null
}

test_supported_os() {
  local os_name=$1
  local os_major=$(echo $2 | cut -f 1 -d . )
  local os_minor=$(echo $2 | cut -f 2 -d . )

  if [ -z "${os_major}" ] ; then
    os_major=0
  fi

  if [ -z "${os_minor}" ] ; then
    os_minor=0
  fi

  # Major version must be a number
  if ! (echo "${os_major}" | grep -q '^[0-9][0-9]*$') ; then
    return 1
  fi

  # Minor version of pre-releases may have non-numeric suffix, e.g.,
  # Alpine 3.12_alpha20200122
  os_minor=$(echo "${os_minor}" | grep -o '^[0-9]*')
  if [ -z "${os_minor}" ] ; then
    return 1
  fi

  case "${os_name}" in
    rhel)
      if [ "${os_major}" -ge 7 ] ; then
        return 0
      fi
      ;;
    ubuntu)
      if [ "${os_major}" -gt 18 -o \
           "${os_major}" -eq 18 -a "${os_minor}" -ge 4 ] ; then
        return 0
      fi
      ;;
    debian)
      if [ "${os_major}" -ge 9 ] ; then
        return 0
      fi
      ;;
    centos)
      if [ "${os_major}" -ge 7 ] ; then
        return 0
      fi
      ;;
    fedora)
      if [ "${os_major}" -ge 19 ] ; then
        return 0
      fi
      ;;
    alpine)
      if [ "${os_major}" -gt 3 -o \
           "${os_major}" -eq 3 -a "${os_minor}" -ge 11 ] ; then
        return 0
      fi
      ;;
    esac
    return 1
}

#
# Gather OS information
#
if [ -r /etc/os-release ]; then
  .     /etc/os-release
  if ! test_supported_os "$ID" "$VERSION_ID" ; then
    LINUX_VERSION=${VERSION:-"$VERSION_ID"}
    echo "WARNING: Veracode SCA agent has not validated support of $ID version $LINUX_VERSION" >&2
  fi
  if [ "$ID" = alpine ] ; then
      tgz_suffix=linux_musl_x64
  else
      tgz_suffix=linux
  fi
else
  # test for centos version 6 that does not have /etc/os-release.
  if [ -r /etc/system-release ] ; then
    ID=$(awk '{print $1;}' /etc/system-release | tr [A-Z] [a-z])
    VERSION_ID=$(awk '{print $3;}' /etc/system-release)
    MAJOR_VERSION=$(echo $VERSION_ID | cut -f 1 -d . )
    if [ "$ID" != centos ] || [ "$MAJOR_VERSION" -lt "7" ] ; then
      echo "Veracode SCA agent has not validated support of $ID version $VERSION_ID"
      exit 1
    fi
    tgz_suffix=linux
  else
    if command_exist sw_vers; then
      # might be a mac
      ID=$(sw_vers | grep ProductName | awk -F':' '{print tolower($2)}' | tr -d '[:space:]')
      VERSION_ID=$(sw_vers | grep ProductVersion | awk -F':' '{print $2}' | tr -d '[:space:]')
      tgz_suffix=macosx
    else
      echo 'WARNING: Veracode SCA agent has not validated installation on this os distribution' >&2
    fi
  fi
fi

if [ -z "$tgz_suffix" ]; then
  echo 'Unrecognized OS; please contact us at <support@sourceclear.com> for troubleshooting' >&2
  exit 1
fi

#
# Fetch the latest srcclr tgz, and continue with local install.
#
LATEST_VERSION=${SRCCLR_VERSION:-$(${CURL_C} --silent ${DOWNLOAD_URL}/LATEST_VERSION)}
if [ "$?" -ne 0 ] ; then
  exit 1
fi

# Use .veracode_tmp directory for extraction
VERACODE_TMP_DIR="${HOME}/.veracode_wrapper"
EXTRACTION_DIR="${VERACODE_TMP_DIR}/srcclr-latest"
mkdir -p "${EXTRACTION_DIR}"

{ cd "${VERACODE_TMP_DIR}"; ${CURL_C} --progress-bar "${DOWNLOAD_URL}/srcclr-${LATEST_VERSION}-${tgz_suffix}.tgz" | tar zxf - -C "${EXTRACTION_DIR}"; }

# Echo message indicating successful installation
echo "srcclr CLI agent was installed properly in ${EXTRACTION_DIR}"


