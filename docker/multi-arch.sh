#!/bin/bash

#change to directory with script so we know where project root is
#https://stackoverflow.com/questions/59895/can-a-bash-script-tell-which-directory-it-is-stored-in
src_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$src_dir"

# Use trow-multi builder if it exists, otherwise create it

if [[ $(docker buildx ls | grep -s trow-multi) != 0 ]]
then
    # Register binfmt handlers
    docker run --rm --privileged aptman/qus -s -- -p arm aarch64
    # Create new build instance
    docker buildx create --name trow-multi
fi
docker buildx use trow-multi

# Github Package Repository doesn't support multi-arch images currently, so on hold
GH_REPO=${DOCKER_REPO:-"docker.pkg.github.com/containersolutions/trow/trow"}
REPO=${DOCKER_REPO:-"containersol/trow"}

# If we're in a github action, set the image name differently
if [[ "$CI" = true ]]
then
    VERSION=$(date +"%Y-%m-%d")-$GITHUB_RUN_NUMBER
else
    VERSION=$(sed '/^version = */!d; s///;q' ../Cargo.toml | sed s/\"//g)
fi

TAG=${DOCKER_TAG:-"$VERSION-armv7"}
IMAGE=${IMAGE_NAME:-"$REPO:$TAG"}
DATE="$(date --rfc-3339=seconds)"
PLATFORM="linux/arm/v7"

docker buildx build \
  --build-arg VCS_REF="${SOURCE_COMMIT:-$(git rev-parse HEAD)}" \
  --build-arg VCS_BRANCH="${SOURCE_BRANCH:-$(git symbolic-ref --short HEAD)}" \
  --build-arg REPO="$REPO" \
  --build-arg TAG="$TAG" \
  --build-arg DATE="$DATE" \
  --build-arg VERSION="$VERSION" \
  --pull --load --platform linux/arm/v7 \
  -f "Dockerfile.armv7" -t $IMAGE ../

if [[ "$CI" = true ]]
then
    docker push $IMAGE
    # Add new image name to manifest template
    sed -i "s|{{TROW_ARMV7_IMAGE}}|${IMAGE}|" ./manifest.tmpl
fi

PLATFORM="linux/arm64"
TAG=${DOCKER_TAG:-"$VERSION-arm64"}
IMAGE=${IMAGE_NAME:-"$REPO:$TAG"}
DATE="$(date --rfc-3339=seconds)"

docker buildx build \
  --build-arg VCS_REF="${SOURCE_COMMIT:-$(git rev-parse HEAD)}" \
  --build-arg VCS_BRANCH="${SOURCE_BRANCH:-$(git symbolic-ref --short HEAD)}" \
  --build-arg REPO="$REPO" \
  --build-arg TAG="$TAG" \
  --build-arg DATE="$DATE" \
  --build-arg VERSION="$VERSION" \
  --pull --load --platform $PLATFORM \
  -f "Dockerfile.arm64" -t $IMAGE ../

if [[ "$CI" = true ]]
then
    docker push $IMAGE
    # Add new image name to manifest template
    sed -i "s|{{TROW_ARM64_IMAGE}}|${IMAGE}|" ./manifest.tmpl
fi
