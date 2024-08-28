#!/bin/bash

IMAGE_VERSION=$1
START_LOCATION=$(pwd)
ENVOY_REPO="/local/$USER/git/5g_proto/devtools/envoy-builder/sc_envoy"
DOCKER_REGISTRY_URL="arm.seli.gic.ericsson.se"
DOCKER_REPO_PATH="proj-5g-bsf"
IMAGE_NAME="eric-scp-envoy-base"
REPOSITORY_NAME="docker-v2-global-local"
RULESET_ENVOY="ruleset2.0-eric-envoy.yaml"
RULESET_ESC="ruleset2.0-eric-esc.yaml"

git::is_dirty() {
  ! (git diff --quiet && git diff --cached --quiet)
}

cd "$ENVOY_REPO"

# split base version and version
if [[ $IMAGE_VERSION =~ (^[0-9]{1}.[0-9]{2}.[0-9]+)-(.*$) ]]; then
  BASE_VERSION="${BASH_REMATCH[1]}"
  VERSION="${BASH_REMATCH[2]}"
  echo $BASE_VERSION
  echo $VERSION
else
  echo "NOT official image"
fi

# check if it's an official version, if so, check if there are uncommited changes
if [[ $IMAGE_VERSION =~ ^[0-9]{1}.[0-9]{2}.[0-9]+-[0-9]+$ ]]; then
	echo "Official image"
  IS_OFFICIAL=true
  echo "${BASH_REMATCH[0]}"
	# (! git::is_dirty) || { echo "ERROR: Cannot create an image with uncommitted changes" ; exit 1; }
else
  IS_OFFICIAL=false
  echo "NOT official image"
fi

# import artifactory tokens
# source /home/$USER/.5g.devenv.profile;

# check if image with specified version already exist
FOUND_VERSIONS=$(curl -s -k -H "X-JFrog-Art-Api:$ARTIFACTORY_TOKEN" https://${DOCKER_REGISTRY_URL}/artifactory/api/docker/${REPOSITORY_NAME}/v2/${DOCKER_REPO_PATH}/envoy/${IMAGE_NAME}/tags/list | jq '.tags' | grep \"${IMAGE_VERSION}\")

if [ -z "$FOUND_VERSIONS" ]; then 
  if [ "$IS_OFFICIAL" = true ] ; then
    echo "Tag does not exist";
    ENVOY_VERSION="envoy-v${IMAGE_VERSION}"
    echo $ENVOY_VERSION
    git tag -a $ENVOY_VERSION -m "New Envoy Image $ENVOY_VERSION"
    git push origin $ENVOY_VERSION
  fi
  cd "/local/$USER/git/5g_proto"
  git pull --rebase --autostash
  sed -i "s/- ENVOY_GIT_TAG:.*/- ENVOY_GIT_TAG: $BASE_VERSION/" $RULESET_ENVOY
  sed -i "s/- ENVOY_VERSION:.*/- ENVOY_VERSION: \${ENVOY_GIT_TAG}-${VERSION}/" $RULESET_ENVOY
  bob/bob -r ruleset2.0-eric-envoy.yaml build-sc-envoy-fips push-images
  if [ "$IS_OFFICIAL" = true ] ; then
    sed -i "s/- ENVOY_VERSION:.*/- ENVOY_VERSION: ${IMAGE_VERSION}/" $RULESET_ESC
    echo "Updating the changelog"
    cd "$ENVOY_REPO/tools"
    python auto-changelog.py
    echo "Packing the protobuf"
    cd "$ENVOY_REPO/api"
    /proj/sc-tools/bin/fd -u '.+\.proto' | tar cvzf /proj/sc-tools/envoy-proto/envoy-proto-$IMAGE_VERSION.tgz -T -
  fi
else 
  echo "The image with specified version already exists"; 
  echo "${FOUND_VERSIONS}"
fi