# Overview

This charm acts as a proxy to OpenStack and provides an [interface][] to provide
a set of credentials for a somewhat limited project user to the applications that
are related to this charm.

## Usage

When on OpenStack, this charm can be deployed, granted trust via Juju to access
OpenStack, and then related to an application that supports the [interface][].

For example, [CDK][] has support for this, and can be deployed with the
following bundle overlay:

```yaml
applications:
  openstack-integrator:
    charm: cs:~containers/openstack-integrator
    num_units: 1
relations:
  - ['openstack-integrator', 'kubernetes-master']
  - ['openstack-integrator', 'kubernetes-worker']
```

Using Juju 2.4-beta1 or later:

```
juju deploy cs:canonical-kubernetes --overlay ./k8s-openstack-overlay.yaml
juju trust openstack-integrator
```

To deploy with earlier versions of Juju, you will need to provide the cloud
credentials via the `credentials`, charm config options.

# Resource Usage Note

By relating to this charm, other charms can directly allocate resources, such
as PersistentDisk volumes and Load Balancers, which could lead to cloud charges
and count against quotas.  Because these resources are not managed by Juju,
they will not be automatically deleted when the models or applications are
destroyed, nor will they show up in Juju's status or GUI.  It is therefore up
to the operator to manually delete these resources when they are no longer
needed, using the OpenStack console or API.

# Examples

Following are some examples using OpenStack integration with CDK.

## Creating a pod with a PersistentDisk-backed volume

This script creates a busybox pod with a persistent volume claim backed by
OpenStack's PersistentDisk.

```sh
#!/bin/bash

# create a storage class using the `kubernetes.io/cinder` provisioner
kubectl create -f - <<EOY
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: openstack-standard
provisioner: kubernetes.io/cinder
EOY

# create a persistent volume claim using that storage class
kubectl create -f - <<EOY
kind: PersistentVolumeClaim
apiVersion: v1
metadata:
  name: testclaim
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 100Mi
  storageClassName: openstack-standard
EOY

# create the busybox pod with a volume using that PVC:
kubectl create -f - <<EOY
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
    - image: busybox
      command:
        - sleep
        - "3600"
      imagePullPolicy: IfNotPresent
      name: busybox
      volumeMounts:
        - mountPath: "/pv"
          name: testvolume
  restartPolicy: Always
  volumes:
    - name: testvolume
      persistentVolumeClaim:
        claimName: testclaim
EOY
```

## Creating a service with a OpenStack load-balancer

The following script starts the hello-world pod behind a OpenStack-backed load-balancer.

```sh
#!/bin/bash

kubectl run hello-world --replicas=5 --labels="run=load-balancer-example" --image=gcr.io/google-samples/node-hello:1.0  --port=8080
kubectl expose deployment hello-world --type=LoadBalancer --name=hello
watch kubectl get svc -o wide --selector=run=load-balancer-example
```


[interface]: https://github.com/juju-solutions/interface-openstack-integration
[CDK]: https://jujucharms.com/canonical-kubernetes
