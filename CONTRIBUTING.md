# Contributor Guide

This Juju charm is open source ([Apache License 2.0](./LICENSE)) and we actively seek any community contibutions
for code, suggestions and documentation.
This page details a few notes, workflows and suggestions for how to make contributions most effective and help us
all build a better charm - please give them a read before working on any contributions.

## Licensing

This charm has been created under the [Apache License 2.0](./LICENSE), which will cover any contributions you may
make to this project. Please familiarise yourself with the terms of the license.

Additionally, this charm uses the Harmony CLA agreement.  It’s the easiest way for you to give us permission to
use your contributions. 
In effect, you’re giving us a license, but you still own the copyright — so you retain the right to modify your
code and use it in other projects. Please [sign the CLA here](https://ubuntu.com/legal/contributors/agreement) before
making any contributions.

## Code of conduct
We have adopted the Ubuntu code of Conduct. You can read this in full [here](https://ubuntu.com/community/code-of-conduct).

## Contributing code

The workflow for contributing code is as follows:

1. [Submit a bug](https://bugs.launchpad.net/charm-openstack-integrator/+filebug) to explain the need for and track the change.
2. Create a branch on your fork of the repo with your changes, including a unit test covering the new or modified code.
3. Submit a PR. The PR description should include a link to the bug on Launchpad.
4. Update the Launchpad bug to include a link to the PR and the `review-needed` tag.
5. Once reviewed and merged, the change will become available on the edge channel and assigned to an appropriate milestone
   for further release according to priority.

## Documentation

Documentation for this charm is currently maintained as part of the Charmed Kubernetes docs.
See [this page](https://github.com/charmed-kubernetes/kubernetes-docs/blob/master/pages/k8s/charm-openstack-integrator.md)


## Testing

All tests are run by [tox][].

### Lint and Unittest

These tests cloud be run by `tox -e lint` and `tox -e unit`, and they do not require
any specific requirements.

### Integration tests

The integration tests deploy charmed-kubernetes and charm-openstack integration.
Tests required to be run on top of OpenStack cloud with credentials for
openstack-integrator, since it is deployed with `--trust`.

```bash
source <path-to-openrc>
tox -e integration
```

[tox]: https://tox.wiki/en/latest/
