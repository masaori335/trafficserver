#!/usr/bin/env zsh

set -e
set -x

zparseopts -E -D -- b=BUILD -build=BUILD \
                    t=TAGBUILD -tagbuild=TAGBUILD \
                    e=TEST -test=TEST \
                    r=PRB -prb=PRB \
                    p:=PR_ID -prid:=PR_ID \
                    y=RELEASE -release=RELEASE \
                    a:=BRANCH -branch:=BRANCH \
                    v:=inVARIATION -variation:=inVARIATION \
                    f:=TEST_FILTER -filter-test:=TEST_FILTER \
                    x:=BREAK_FIX -breakfix:=BREAK_FIX \
                    z:=BUILD_NUMBER -number:=BUILD_NUMBER

if (( $# )); then
    end_opts=$@[(i)(--|-)]
    if [[ -n ${invalid_opt::=${(M)@[0,end_opts-1]#-}} ]]; then
        echo >&2 "Invalid options: $invalid_opt"
        exit 1
    fi
    set -- "${@[0,end_opts-1]}" "${@[end_opts+1,-1]}"
fi

# this will only work on rhel-derived-linuxes
if grep -q "release 9" /etc/redhat-release; then
  OSRELEASE="9"
else
  echo "Currently only supports rhel9 builds"
  exit 1
fi


QUICHE_VERSION=0.24.4
BORINGSSL_VERSION=40.20260423
LIBURING_VERSION=2.4
BUILD=${#BUILD}
PRB=${#PRB}
TAGBUILD=${#TAGBUILD}
TEST=${#TEST}
RELEASE=${#RELEASE}
BRANCH=${BRANCH[-1]}
PR_ID=${PR_ID[-1]:=${GIT_PR_ID}}
TEST_FILTER=${TEST_FILTER[-1]}
BREAK_FIX=${BREAK_FIX[-1]}
BUILD_NUMBER=${BUILD_NUMBER[-1]}

inVARIATION=${inVARIATION[-1]}
if [[ ! -z ${inVARIATION} && ! "$inVARIATION" = "default" ]]; then
  VARIATION=${inVARIATION}
fi
export VARIATION
echo VARIATION: $VARIATION

# Resolv build number
# for non-release builds we can use the rio build number
# release builds must pass the real number in
if [ $RELEASE -ne 1 ]; then
  BUILD_NUMBER=${RIO_BUILD_NUMBER:-1}
else
  if [ -z ${BUILD_NUMBER} ]; then
    echo "BUILD_NUMBER not set!"
    exit 1
  fi
fi

git checkout $BRANCH

if [[ ! -z $PR_ID && $PR_ID -gt 0 ]]; then
  git fetch origin pull/${PR_ID}/head
  git merge FETCH_HEAD -m 'Auto Merge: PR ${PR_ID}'
fi

function parse_version() {
    awk -F ' |)' '/^project/ { print $3 }' CMakeLists.txt
}

VERSION=$(parse_version)
COMMIT_TREE_LENGTH=$(git --git-dir=.git rev-list HEAD 2>/dev/null | wc -l)
if [ -z ${BREAK_FIX} ]; then
  BUILD_VERSION="${BUILD_NUMBER}.${COMMIT_TREE_LENGTH}"
else
  BUILD_VERSION=${BREAK_FIX}.${BUILD_NUMBER}.${COMMIT_TREE_LENGTH}
fi
export BUILD_VERSION

export GIT_TAG=bazinga/$VERSION/$BUILD_VERSION
if [ $PRB -eq 1 ]; then
    export GIT_TAG=prb/$VERSION/$BUILD_VERSION
fi

if [ ! -z "$VARIATION" ]; then
    export GIT_TAG=bazinga/$VERSION/${VARIATION}.$BUILD_VERSION
fi

LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-boringssl-devel-${BORINGSSL_VERSION}
LD_LIBRARY_PATH=/lib64 yum erase -d1 -y bazinga-openssl-devel

# Temp remove fmt and install bazinga-fmt until build image updates
yum remove -y fmt fmt-devel
LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-liburing-devel-${LIBURING_VERSION} bazinga-fmt-devel

# copy user presets
cp apple/CMakeUserPresets.json .

if [ $BUILD -eq 1 ]; then
  export LIBURING_VERSION
  export QUICHE_VERSION
  export BORINGSSL_VERSION
  export OSRELEASE
  export VARIATION
  if [[ ! -z $PR_ID && $PR_ID -gt 0 ]]; then
     ./apple/build.sh $BUILD_VERSION $PR_ID
  else
     ./apple/build.sh $BUILD_VERSION
  fi
fi

# If prb or test, skip staging artifacts
if [[ $PRB -ne 1 && $TEST -ne 1 ]]; then
  # Stage build
  mv build/rpmbuild/RPMS/* build/rpmbuild/
  ci stage-lib build/rpmbuild/x86_64,ci/el/$OSRELEASE/x86_64
  ci stage-lib build/rpmbuild/SRPMS,ci/el/$OSRELEASE/SRPMS
fi

if [ $TAGBUILD -eq 1 ]; then
  export GIT_TAG=$GIT_TAG.el$OSRELEASE
  git tag $GIT_TAG
  SSH_AUTH_SOCK=${SSH_AUTH_SOCK_TRAFFICSERVER} git push origin $GIT_TAG
  cd ..
fi

if [ $TEST -eq 1 ]; then
  update-crypto-policies --set DEFAULT:SHA1
  ./apple/run_autest.sh "$TEST_FILTER"
fi
