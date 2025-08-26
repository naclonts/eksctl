package iamoidc

import (
	"fmt"
	"net/url"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Additional tests for the OIDC fallback mechanism
// These tests are integrated into the existing test suite

var _ = Describe("OIDC Fallback Mechanism", func() {
	Describe("isDNSError", func() {
		It("should return true for DNS-related errors", func() {
			// Test with error message containing "no such host"
			err := fmt.Errorf("dial tcp: lookup oidc.eks.us-east-1.amazonaws.com on 192.168.0.2:53: no such host")
			Expect(isDNSError(err)).To(BeTrue())

			// Test with error message containing "nxdomain"
			err = fmt.Errorf("lookup failed: nxdomain")
			Expect(isDNSError(err)).To(BeTrue())

			// Test with error message containing "name resolution"
			err = fmt.Errorf("name resolution failed")
			Expect(isDNSError(err)).To(BeTrue())
		})

		It("should return false for non-DNS errors", func() {
			// Test with connection timeout
			err := fmt.Errorf("dial tcp: i/o timeout")
			Expect(isDNSError(err)).To(BeFalse())

			// Test with nil error
			Expect(isDNSError(nil)).To(BeFalse())

			// Test with other network errors
			err = fmt.Errorf("connection refused")
			Expect(isDNSError(err)).To(BeFalse())
		})
	})

	Describe("constructAlternativeURL", func() {
		var manager *OpenIDConnectManager

		BeforeEach(func() {
			manager = &OpenIDConnectManager{}
		})

		It("should construct correct alternative URL for standard regions", func() {
			testCases := []struct {
				originalURL string
				expectedURL string
				description string
			}{
				{
					originalURL: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE123456789",
					expectedURL: "https://eks.us-east-1.api.aws:443/id/EXAMPLE123456789",
					description: "us-east-1 region",
				},
				{
					originalURL: "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLE123456789",
					expectedURL: "https://eks.us-west-2.api.aws:443/id/EXAMPLE123456789",
					description: "us-west-2 region",
				},
				{
					originalURL: "https://oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLE123456789",
					expectedURL: "https://eks.eu-west-1.api.aws:443/id/EXAMPLE123456789",
					description: "eu-west-1 region",
				},
				{
					originalURL: "https://oidc.eks.ap-southeast-1.amazonaws.com/id/EXAMPLE123456789",
					expectedURL: "https://eks.ap-southeast-1.api.aws:443/id/EXAMPLE123456789",
					description: "ap-southeast-1 region",
				},
			}

			for _, tc := range testCases {
				issuerURL, err := url.Parse(tc.originalURL)
				Expect(err).NotTo(HaveOccurred())

				manager.issuerURL = issuerURL
				alternativeURL, err := manager.constructAlternativeURL()
				Expect(err).NotTo(HaveOccurred())
				Expect(alternativeURL).To(Equal(tc.expectedURL), fmt.Sprintf("Failed for %s", tc.description))
			}
		})

		It("should return error for invalid URL formats", func() {
			testCases := []struct {
				invalidURL  string
				description string
			}{
				{
					invalidURL:  "https://invalid.eks.us-east-1.amazonaws.com/id/EXAMPLE123456789",
					description: "wrong prefix",
				},
				{
					invalidURL:  "https://oidc.eks.us-east-1.example.com/id/EXAMPLE123456789",
					description: "wrong suffix",
				},
				{
					invalidURL:  "https://oidc.eks..amazonaws.com/id/EXAMPLE123456789",
					description: "empty region",
				},
				{
					invalidURL:  "https://example.com/id/EXAMPLE123456789",
					description: "completely different format",
				},
			}

			for _, tc := range testCases {
				issuerURL, err := url.Parse(tc.invalidURL)
				Expect(err).NotTo(HaveOccurred())

				manager.issuerURL = issuerURL
				_, err = manager.constructAlternativeURL()
				Expect(err).To(HaveOccurred(), fmt.Sprintf("Should fail for %s", tc.description))
			}
		})
	})
})
