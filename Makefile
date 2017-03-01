#all: push
all: controller

# 0.0 shouldn't clobber any release builds
TAG = 0.22
PREFIX = chiradeep/kube-policy-manager

controller_linux: controller.go main.go
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w' -o kube-policy-manager

controller: controller.go utils.go main.go
	go build  -o kube-policy-manager

container: controller_linux
	sudo docker build -t $(PREFIX):$(TAG) .

#push: container
#	gcloud docker push $(PREFIX):$(TAG)

clean:
	rm -f kube-policy-manager

run:
	./kube-policy-manager --logtostderr=1
