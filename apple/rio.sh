#!/usr/bin/env zsh

set -e
set -x

zparseopts -E -D -- b=BUILD -build=BUILD \
                    t=TAGBUILD -tagbuild=TAGBUILD \
                    e=TEST -test=TEST \
                    r=PRB -prb=PRB \
                    p:=PR_ID -prid:=PR_ID \
                    a:=BRANCH -branch:=BRANCH \
                    v:=inVARIATION -variation:=inVARIATION \
                    f:=TEST_FILTER -filter-test:=TEST_FILTER
if (( $# )); then
    end_opts=$@[(i)(--|-)]
    if [[ -n ${invalid_opt::=${(M)@[0,end_opts-1]#-}} ]]; then
        echo >&2 "Invalid options: $invalid_opt"
        exit 1
    fi
    set -- "${@[0,end_opts-1]}" "${@[end_opts+1,-1]}"
fi

BUILD=${#BUILD}
PRB=${#PRB}
TAGBUILD=${#TAGBUILD}
TEST=${#TEST}
BRANCH=${BRANCH[-1]}
PR_ID=${PR_ID[-1]:=${GIT_PR_ID}}
TEST_FILTER=${TEST_FILTER[-1]}

inVARIATION=${inVARIATION[-1]}
if [[ ! -z ${inVARIATION} ]]; then
  VARIATION=${inVARIATION}
fi
export VARIATION
echo VARIATION: $VARIATION

RIO_BUILD_NUMBER=${RIO_BUILD_NUMBER:-1}

# Setup tree
if [ ! -f trafficserver/configure.ac ]; then
  git clone -q git@github.pie.apple.com:ats/trafficserver.git
fi

cd trafficserver
git checkout $BRANCH

if [[ ! -z $PR_ID && $PR_ID -gt 0 ]]; then
  git fetch origin pull/${PR_ID}/head
  git merge FETCH_HEAD -m 'Auto Merge: PR ${PR_ID}'
fi

cd ..

VERSION=$(grep '\[TS_VERSION_S\]' trafficserver/configure.ac | head -n 1 | perl -pe 's{^.*\],\[(\d+.\d+.\d+).*$}{$1}')
COMMIT_TREE_LENGTH=$(git --git-dir=trafficserver/.git rev-list HEAD 2>/dev/null | wc -l)
BUILD_VERSION="${RIO_BUILD_NUMBER}.${COMMIT_TREE_LENGTH}"
export BUILD_VERSION

export GIT_TAG=bazinga/$VERSION/$BUILD_VERSION
if [ $PRB -eq 1 ]; then
    export GIT_TAG=prb/$VERSION/$BUILD_VERSION
fi

if [ "$VARIATION" = "-boringssl" ]; then
    LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-boringssl bazinga-boringocsp
    LD_LIBRARY_PATH=/lib64 yum erase -d1 -y bazinga-openssl-devel
fi

if [ "$VARIATION" = "-io_uring" ]; then
    LD_LIBRARY_PATH=/lib64 yum install -d1 -y --disablerepo=\* --enablerepo=artifactory-ci bazinga-liburing bazinga-liburing-devel
fi

if [ $BUILD -eq 1 ]; then
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
  ci stage-lib build/rpmbuild/x86_64,ci/el/7/x86_64
  ci stage-lib build/rpmbuild/SRPMS,ci/el/7/SRPMS
fi

if [ $TAGBUILD -eq 1 ]; then
  cd trafficserver
  git tag $GIT_TAG
  SSH_AUTH_SOCK=${SSH_AUTH_SOCK_TRAFFICSERVER} git push origin $GIT_TAG
  cd ..
fi

if [ $TEST -eq 1 ]; then
  scl enable rh-python38 "./apple/run_autest.sh '$TEST_FILTER'"
fi
