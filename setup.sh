# Initialize variables
# Run 'doctl compute region list' for a list of available regions
REGION=lon1

MASTER_NAME=k8s-master
NODE_PREFIX=k8s-node
NODE_COUNT=${NODE_COUNT:-2}
LOCAL_SSH_KEY=${LOCAL_SSH_KEY:-~/.ssh/id_rsa.pub}
SSH_KEY_NAME=k8s-ssh

MASTER_TAG=k8s-master
NODE_TAG=k8s-node

DROPLET_IMAGE=ubuntu-16-04-x64
DROPLET_SIZE=2gb

# Download DigitalOcean CLI
if !command -v doctl >/dev/null 2>&1; then
    curl -L https://github.com/digitalocean/doctl/releases/download/v1.7.0/doctl-1.7.0-linux-amd64.tar.gz | tar xz
    sudo mv ~/doctl /usr/local/bin
fi

# Download Kubectl
if !command -v kubectl >/dev/null 2>&1; then
    curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    sudo mv ./kubectl /usr/local/bin/kubectl
fi

if ! grep --silent --line-regexp "$SSH_KEY_NAME" <(doctl compute ssh-key list --no-header --format Name); then
    echo "Generating new SSH key $SSH_KEY_NAME"
    echo "Not actually, need to fix this"
    exit # TODO
    # Generate SSH Keys
    ssh-keygen -t rsa

    # Import SSH Keys
    doctl compute ssh-key import $SSH_KEY_NAME --public-key-file "$LOCAL_SSH_KEY"
else
    echo "Key $SSH_KEY_NAME already exists, not recreating"
fi
SSH_ID=`doctl compute ssh-key list | grep "$SSH_KEY_NAME" | cut -d' ' -f1`
SSH_KEY=`doctl compute ssh-key get $SSH_ID --format FingerPrint --no-header`

# Create Tags
if ! grep --silent $MASTER_TAG <(doctl compute tag list); then
    doctl compute tag create $MASTER_TAG
fi
if ! grep --silent $NODE_TAG <(doctl compute tag list); then
    doctl compute tag create $NODE_TAG
fi

# Generate token and insert into the script files
if grep --silent --line-regexp "TOKEN=xxxxxx.yyyyyyyyyyyyyyyy" master.sh; then
    echo "Generating a new TOKEN"
    while ! [[ $TOKEN =~ ^([a-z0-9]{6})\.([a-z0-9]{16})$ ]]; do
        TOKEN=`python -c 'import random; print "%0x.%0x" % (random.SystemRandom().getrandbits(3*8), random.SystemRandom().getrandbits(8*8))'`
    done
    sed -i "s/^TOKEN=.*/TOKEN=${TOKEN}/" master.sh
    sed -i "s/^TOKEN=.*/TOKEN=${TOKEN}/" node.sh
else
    TOKEN=$(grep --line-regexp "TOKEN=\([a-z0-9]\{6\}\)\.\([a-z0-9]\{16\}\)" master.sh | cut -d= -f2)
fi
if [ -z $TOKEN ]; then
    echo "No token available"
    exit 1
fi

if ! grep --silent --line-regexp "$MASTER_NAME" <(doctl compute droplet list --no-header --format Name); then
    # Create Master
    # TODO, do we need public networking?
    doctl compute droplet create "$MASTER_NAME" \
            --region $REGION \
            --enable-ipv6 \
            --enable-monitoring \
            --enable-private-networking \
            --image $DROPLET_IMAGE \
            --size $DROPLET_SIZE \
            --tag-name $MASTER_TAG \
            --ssh-keys $SSH_KEY \
            --user-data-file  ./master.sh \
            --wait
fi

while [ -z "$MASTER_IP_PRIVATE" ]; do
    # Retrieve IP address of Master
    MASTER_ID=`doctl compute droplet list | grep "$MASTER_NAME" |cut -d' ' -f1`
    MASTER_IP_PUBLIC=`doctl compute droplet get $MASTER_ID --format PublicIPv4 --no-header`
    MASTER_IP_PRIVATE=`doctl compute droplet get $MASTER_ID --format PrivateIPv4 --no-header`
    if [ -z "$MASTER_IP_PRIVATE" ]; then
        echo "Master IP not yet available..."
        sleep 3
    fi
done

# Run this after a few minutes. Wait till Kubernetes Master is up and running
while ! scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$LOCAL_SSH_KEY" root@$MASTER_IP_PUBLIC:/etc/kubernetes/admin.conf .; do
    echo "kubectl conf not yet available..."
    sleep 30
done

if ! grep --silent --line-regexp "MASTER_IP=${MASTER_IP_PRIVATE}" node.sh; then
    # Update Script with MASTER_IP_PRIVATE
    sed -i "s/^MASTER_IP=.*/MASTER_IP=${MASTER_IP_PRIVATE}/" node.sh
fi

# Create nodes
nodes=$(seq --format "$NODE_PREFIX%g" 1 $NODE_COUNT)
do_nodes=$(doctl compute droplet list --no-header --format Name)
for node in $nodes; do
    if ! grep --silent --line-regexp "$node" <(echo -e "$do_nodes"); then
        echo "Creating $node"
        # TODO, do we need public networking?
        doctl compute droplet create $node \
                --region $REGION \
                --enable-ipv6 \
                --enable-monitoring \
                --enable-private-networking \
                --image $DROPLET_IMAGE \
                --size $DROPLET_SIZE \
                --tag-name $NODE_TAG \
                --ssh-keys $SSH_KEY \
                --user-data-file  ./node.sh \
                --wait
    fi
done

# ~5min

# Confirm the creation of Nodes
kubectl --kubeconfig ./admin.conf get nodes

echo "Setup complete!"
exit

# Deploy an App
kubectl --kubeconfig ./admin.conf create  -f todo-all-in-one.yaml

# TODO wait until there is a port

# Get the NodePort
NODEPORT=`kubectl --kubeconfig ./admin.conf get svc -o go-template='{{range .items}}{{range.spec.ports}}{{if .nodePort}}{{.nodePort}}{{"\n"}}{{end}}{{end}}{{end}}'`

# Create a Load Balancer
doctl compute load-balancer create \
	--name k8slb \
	--tag-name k8s-node \
	--region $REGION \
	--health-check protocol:http,port:$NODEPORT,path:/,check_interval_seconds:10,response_timeout_seconds:5,healthy_threshold:5,unhealthy_threshold:3 \
	--forwarding-rules entry_protocol:TCP,entry_port:80,target_protocol:TCP,target_port:$NODEPORT

# TODO wait until the LB has an IP

# Open the Web App in Browser
LB_ID=`doctl compute load-balancer list | grep "k8slb" | cut -d' ' -f1`
LB_IP=`doctl compute load-balancer get $LB_ID | awk '{ print $2; }' | tail -n +2`
open http://$LB_IP
