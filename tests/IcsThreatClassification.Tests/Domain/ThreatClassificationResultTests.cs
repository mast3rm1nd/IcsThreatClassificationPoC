using FluentAssertions;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using Xunit;

namespace IcsThreatClassification.Tests.Domain;

public sealed class ThreatClassificationResultTests
{
    [Fact]
    public void Constructor_ValidParameters_CreatesResult()
    {
        var result = new ThreatClassificationResult(
            IcsThreatType.DenialOfService,
            0.85,
            "Test explanation");

        result.ThreatType.Should().Be(IcsThreatType.DenialOfService);
        result.Confidence.Should().Be(0.85);
        result.Explanation.Should().Be("Test explanation");
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(1.1)]
    [InlineData(2.0)]
    public void Constructor_InvalidConfidence_ThrowsException(double confidence)
    {
        var action = () => new ThreatClassificationResult(
            IcsThreatType.DenialOfService,
            confidence,
            "Test");

        action.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void IsThreatDetected_WhenThreatTypeIsNone_ReturnsFalse()
    {
        var result = ThreatClassificationResult.NoThreat();

        result.IsThreatDetected.Should().BeFalse();
    }

    [Theory]
    [InlineData(IcsThreatType.DenialOfService)]
    [InlineData(IcsThreatType.RansomwareActivity)]
    [InlineData(IcsThreatType.DataExfiltration)]
    public void IsThreatDetected_WhenThreatTypeIsNotNone_ReturnsTrue(IcsThreatType threatType)
    {
        var result = new ThreatClassificationResult(threatType, 0.8, "Test");

        result.IsThreatDetected.Should().BeTrue();
    }

    [Fact]
    public void NoThreat_ReturnsNoneTypeWithFullConfidence()
    {
        var result = ThreatClassificationResult.NoThreat();

        result.ThreatType.Should().Be(IcsThreatType.None);
        result.Confidence.Should().Be(1.0);
    }
}
