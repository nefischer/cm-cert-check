package main

import (
	"cm-cert-check/certcheck"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func newLogger() *logrus.Logger {
	var logger = logrus.New()
	logger.Out = os.Stderr
	jsonFormatter := new(logrus.JSONFormatter)
	jsonFormatter.TimestampFormat = time.RFC3339Nano
	logger.Formatter = jsonFormatter
	logger.Level = logrus.InfoLevel
	return logger
}

var (
	kubeconfigPath = flag.String("kubeconfig", fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".kube/config"), "Path to kubeconfig file if running outside the Kubernetes cluster")
	kubeContext    = flag.String("context", "", "kube context to use (uses current context if not specified)")
)

func main() {
	flag.Parse()

	logger := newLogger()

	logger.Infof("Using kube context %s", *kubeContext)

	kubeClientset, err := certcheck.GetKubeClientSet(*kubeconfigPath, *kubeContext)
	if err != nil {
		logger.Fatalf("Error creating Kubernetes client, exiting: %v", err)
	}
	
	cmioClient, err := certcheck.GetCmioClient()
	if err != nil {
		logger.Fatalf("Error creating cert-manager client, exiting: %v", err)
	}

	checker := certcheck.IngressCertificateChecker{
		Logger:     logger,
		KubeClient: kubeClientset,
		CmioClient: cmioClient,
		CertManagerLabelFilter: []certcheck.CertManagerFilter{
			{
				Key:          "stable.k8s.psg.io/kcm.class",
				Value:        "default",
				FriendlyName: "psg-kcm",
			},
		},
		CertManagerAnnotationsFilter: []certcheck.CertManagerFilter{
			{
				Key:          "certmanager.k8s.io/enabled",
				Value:        "true",
				FriendlyName: "js-cm-legacy",
			},
			{
				Key:          "cert-manager.io/enabled",
				Value:        "true",
				FriendlyName: "js-cmio",
			},
		},
		Ctx: context.TODO(),
	}

	checker.Run()
}
