using FluentAssertions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.MlEngine.Data;
using Xunit;

namespace IcsThreatClassification.Tests.Data;

public sealed class SyntheticDatasetGeneratorTests
{
    private readonly SyntheticDatasetGenerator _generator = new();

    [Fact]
    public void Generate_ReturnsCorrectTotalSampleCount()
    {
        var options = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 100,
            Seed = 42
        };

        var dataset = _generator.Generate(options);

        int expectedCount = Enum.GetValues<IcsThreatType>().Length * 100;
        dataset.Should().HaveCount(expectedCount);
    }

    [Fact]
    public void Generate_ContainsSamplesForAllThreatTypes()
    {
        var options = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 50,
            Seed = 42
        };

        var dataset = _generator.Generate(options);

        var threatTypes = Enum.GetValues<IcsThreatType>();

        foreach (var threatType in threatTypes)
        {
            dataset.Count(s => s.Label == threatType)
                .Should().Be(50, $"because {threatType} should have exactly 50 samples");
        }
    }

    [Theory]
    [InlineData(IcsThreatType.UnauthorizedRemoteAccess)]
    [InlineData(IcsThreatType.MaliciousCommandInjection)]
    [InlineData(IcsThreatType.ConfigurationTampering)]
    [InlineData(IcsThreatType.DenialOfService)]
    [InlineData(IcsThreatType.RansomwareActivity)]
    [InlineData(IcsThreatType.DataExfiltration)]
    [InlineData(IcsThreatType.ManInTheMiddle)]
    [InlineData(IcsThreatType.ProtocolMisuse)]
    [InlineData(IcsThreatType.BruteForceAuthentication)]
    [InlineData(IcsThreatType.SuspiciousEngineeringWorkstationActivity)]
    [InlineData(IcsThreatType.None)]
    public void Generate_EachThreatTypeHasCorrectSampleCount(IcsThreatType threatType)
    {
        var options = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 25,
            Seed = 42
        };

        var dataset = _generator.Generate(options);

        dataset.Count(s => s.Label == threatType).Should().Be(25);
    }

    [Fact]
    public void Generate_WithSameSeed_ProducesDeterministicResults()
    {
        var options1 = new SyntheticDatasetOptions { SamplesPerThreatType = 10, Seed = 12345 };
        var options2 = new SyntheticDatasetOptions { SamplesPerThreatType = 10, Seed = 12345 };

        var dataset1 = _generator.Generate(options1).ToList();
        var dataset2 = _generator.Generate(options2).ToList();

        for (int i = 0; i < dataset1.Count; i++)
        {
            dataset1[i].Label.Should().Be(dataset2[i].Label);
            dataset1[i].Features.AveragePacketSize.Should().Be(dataset2[i].Features.AveragePacketSize);
        }
    }

    [Fact]
    public void Generate_FeaturesAreWithinValidRanges()
    {
        var options = new SyntheticDatasetOptions
        {
            SamplesPerThreatType = 100,
            Seed = 42
        };

        var dataset = _generator.Generate(options);

        foreach (var sample in dataset)
        {
            sample.Features.AveragePacketSize.Should().BeInRange(10f, 1500f);
            sample.Features.SuspiciousCommandCount.Should().BeGreaterThanOrEqualTo(0);
            sample.Features.FailedLoginRate.Should().BeInRange(0f, 1f);
            sample.Features.TrafficToEngineeringStationsRatio.Should().BeInRange(0f, 1f);
            sample.Features.PlcConfigChangeRate.Should().BeInRange(0f, 1f);
            sample.Features.HmiScreenChangeRate.Should().BeInRange(0f, 1f);
            sample.Features.EncryptedTrafficRatio.Should().BeInRange(0f, 1f);
            sample.Features.ExternalConnectionCount.Should().BeGreaterThanOrEqualTo(0);
            sample.Features.BroadcastTrafficRatio.Should().BeInRange(0f, 1f);
            sample.Features.ProtocolViolationScore.Should().BeInRange(0f, 1f);
            sample.Features.DataExfiltrationVolume.Should().BeGreaterThanOrEqualTo(0f);
            sample.Features.CpuLoadAnomalyScore.Should().BeInRange(0f, 1f);
            sample.Features.ProcessValueAnomalyScore.Should().BeInRange(0f, 1f);
            sample.Features.ConnectionRate.Should().BeGreaterThanOrEqualTo(0f);
            sample.Features.DistinctProtocolCount.Should().BeGreaterThanOrEqualTo(1);
        }
    }
}
