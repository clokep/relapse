#!/usr/bin/env bash
#
# A script which checks that an appropriate news file has been added on this
# branch.

echo -e "+++ \033[32mChecking newsfragment\033[m"

set -e

# make sure that origin/develop is up to date
git remote set-branches --add origin develop
git fetch -q origin develop

pr="$PULL_REQUEST_NUMBER"

# if there are changes in the debian directory, check that the debian changelog
# has been updated
if ! git diff --quiet FETCH_HEAD... -- debian; then
    if git diff --quiet FETCH_HEAD... -- debian/changelog; then
        echo "Updates to debian directory, but no update to the changelog." >&2
        echo "!! Please see the contributing guide for help writing your changelog entry:" >&2
        echo "https://clokep.github.io/relapse/latest/development/contributing_guide.html#debian-changelog" >&2
        exit 1
    fi
fi

# if there are changes *outside* the debian directory, check that the
# newsfragments have been updated.
if ! git diff --name-only FETCH_HEAD... | grep -qv '^debian/'; then
    exit 0
fi

# Print a link to the contributing guide if the user makes a mistake
CONTRIBUTING_GUIDE_TEXT="!! Please see the contributing guide for help writing your changelog entry:
https://clokep.github.io/relapse/latest/development/contributing_guide.html#changelog"

# If check-newsfragment returns a non-zero exit code, print the contributing guide and exit
python -m towncrier.check --compare-with=origin/develop || (echo -e "$CONTRIBUTING_GUIDE_TEXT" >&2 && exit 1)

echo
echo "--------------------------"
echo

matched=0
for f in $(git diff --diff-filter=d --name-only FETCH_HEAD... -- changelog.d); do
    # check that any added newsfiles on this branch end with a full stop.
    lastchar=$(tr -d '\n' < "$f" | tail -c 1)
    if [ "$lastchar" != '.' ] && [ "$lastchar" != '!' ]; then
        echo -e "\e[31mERROR: newsfragment $f does not end with a '.' or '!'\e[39m" >&2
        echo -e "$CONTRIBUTING_GUIDE_TEXT" >&2
        exit 1
    fi

    # see if this newsfile corresponds to the right PR
    [[ -n "$pr" && "$f" == changelog.d/"$pr".* ]] && matched=1
done

if [[ -n "$pr" && "$matched" -eq 0 ]]; then
    echo -e "\e[31mERROR: Did not find a news fragment with the right number: expected changelog.d/$pr.*.\e[39m" >&2
    echo -e "$CONTRIBUTING_GUIDE_TEXT" >&2
    exit 1
fi
