# -*- mode: ruby -*-
# vi: set ft=ruby :

$provision = <<SCRIPT
apt-get update -qq && apt-get install -y vim curl python-software-properties golang 
add-apt-repository -y "deb https://get.docker.io/ubuntu docker main"
curl -s https://get.docker.io/gpg | sudo apt-key add -
apt-get update -qq; apt-get install -y lxc-docker
docker pull ubuntu
cat > /etc/profile.d/envvar.sh <<'EOF'
export GOPATH=/opt/golang
export PATH=$PATH:$GOPATH/bin
EOF
. /etc/profile.d/envvar.sh
go get "github.com/milosgajdos83/tenus"
SCRIPT

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "ubuntu/trusty64"
  config.vm.hostname = "tenus"
  config.vm.network :private_network, ip: "10.0.2.88"
  config.vm.network :private_network, ip: "10.0.2.89"

  config.vm.provider "virtualbox" do |v|
    v.customize ['modifyvm', :id, '--nicpromisc1', 'allow-all']
  end

  config.vm.provision "shell", inline: $provision
end
