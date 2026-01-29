using FluentAssertions;
using IcsThreatClassification.Domain.ValueObjects;
using Xunit;

namespace IcsThreatClassification.Tests.Domain;

public sealed class SensorFeatureVectorTests
{
    [Fact]
    public void ToArray_ReturnsCorrectNumberOfFeatures()
    {
        var vector = new SensorFeatureVector
        {
            AveragePacketSize = 100f,
            SuspiciousCommandCount = 5,
            FailedLoginRate = 0.1f,
            TrafficToEngineeringStationsRatio = 0.2f,
            PlcConfigChangeRate = 0.3f,
            HmiScreenChangeRate = 0.4f,
            EncryptedTrafficRatio = 0.5f,
            ExternalConnectionCount = 3,
            BroadcastTrafficRatio = 0.1f,
            ProtocolViolationScore = 0.2f,
            DataExfiltrationVolume = 10f,
            CpuLoadAnomalyScore = 0.3f,
            ProcessValueAnomalyScore = 0.4f,
            ConnectionRate = 20f,
            DistinctProtocolCount = 4
        };

        var array = vector.ToArray();

        array.Should().HaveCount(SensorFeatureVector.FeatureCount);
    }

    [Fact]
    public void FeatureNames_ReturnsCorrectCount()
    {
        SensorFeatureVector.FeatureNames.Should().HaveCount(SensorFeatureVector.FeatureCount);
    }

    [Fact]
    public void ToArray_PreservesFeatureOrder()
    {
        var vector = new SensorFeatureVector
        {
            AveragePacketSize = 100f,
            SuspiciousCommandCount = 5,
            FailedLoginRate = 0.1f,
            TrafficToEngineeringStationsRatio = 0.2f,
            PlcConfigChangeRate = 0.3f,
            HmiScreenChangeRate = 0.4f,
            EncryptedTrafficRatio = 0.5f,
            ExternalConnectionCount = 3,
            BroadcastTrafficRatio = 0.15f,
            ProtocolViolationScore = 0.25f,
            DataExfiltrationVolume = 10f,
            CpuLoadAnomalyScore = 0.35f,
            ProcessValueAnomalyScore = 0.45f,
            ConnectionRate = 20f,
            DistinctProtocolCount = 4
        };

        var array = vector.ToArray();

        array[0].Should().Be(100f);
        array[1].Should().Be(5f);
        array[2].Should().Be(0.1f);
    }
}
