package main

import (
    "cm-cert-check/certcheck"
    "flag"
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
    kubeconfigPath = flag.String("kubeconfig", "", "Path to kubeconfig file if running outside the Kubernetes cluster")
)

func main() {
    flag.Parse()
    
    logger := newLogger()
    
    cli, err := certcheck.NewClientSet(*kubeconfigPath)
    if err != nil {
        logger.Fatalf("Error creating Kubernetes client, exiting: %v", err)
    }
    
    checker := certcheck.IngressCertificateChecker{
        Logger:     logger,
        KubeClient: cli,
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
                FriendlyName: "js-cm-v0.8",
            },
        },
    }
    
    checker.Run()
}
