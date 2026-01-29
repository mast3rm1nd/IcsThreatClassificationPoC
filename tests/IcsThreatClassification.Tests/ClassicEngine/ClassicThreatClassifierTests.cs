using FluentAssertions;
using IcsThreatClassification.ClassicEngine;
using IcsThreatClassification.Domain.Entities;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.ValueObjects;
using Xunit;

namespace IcsThreatClassification.Tests.ClassicEngine;

public sealed class ClassicThreatClassifierTests
{
    private readonly ClassicThreatClassifier _classifier = new();

    [Fact]
    public void Classify_NullReading_ThrowsArgumentNullException()
    {
        var action = () => _classifier.Classify(null!);

        action.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Classify_NormalTraffic_ReturnsNoThreat()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 250f,
            SuspiciousCommandCount = 0,
            FailedLoginRate = 0.01f,
            TrafficToEngineeringStationsRatio = 0.05f,
            PlcConfigChangeRate = 0.02f,
            HmiScreenChangeRate = 0.03f,
            EncryptedTrafficRatio = 0.02f,
            ExternalConnectionCount = 0,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.01f,
            DataExfiltrationVolume = 0.5f,
            CpuLoadAnomalyScore = 0.03f,
            ProcessValueAnomalyScore = 0.02f,
            ConnectionRate = 5f,
            DistinctProtocolCount = 3
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.None);
    }

    [Fact]
    public void Classify_UnauthorizedRemoteAccess_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 400f,
            SuspiciousCommandCount = 1,
            FailedLoginRate = 0.25f,
            TrafficToEngineeringStationsRatio = 0.6f,
            PlcConfigChangeRate = 0.1f,
            HmiScreenChangeRate = 0.1f,
            EncryptedTrafficRatio = 0.7f,
            ExternalConnectionCount = 15,
            BroadcastTrafficRatio = 0.1f,
            ProtocolViolationScore = 0.1f,
            DataExfiltrationVolume = 5f,
            CpuLoadAnomalyScore = 0.2f,
            ProcessValueAnomalyScore = 0.1f,
            ConnectionRate = 15f,
            DistinctProtocolCount = 4
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.UnauthorizedRemoteAccess);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_MaliciousCommandInjection_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 180f,
            SuspiciousCommandCount = 20,
            FailedLoginRate = 0.05f,
            TrafficToEngineeringStationsRatio = 0.2f,
            PlcConfigChangeRate = 0.8f,
            HmiScreenChangeRate = 0.2f,
            EncryptedTrafficRatio = 0.1f,
            ExternalConnectionCount = 1,
            BroadcastTrafficRatio = 0.05f,
            ProtocolViolationScore = 0.7f,
            DataExfiltrationVolume = 1f,
            CpuLoadAnomalyScore = 0.3f,
            ProcessValueAnomalyScore = 0.7f,
            ConnectionRate = 8f,
            DistinctProtocolCount = 3
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.MaliciousCommandInjection);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_ConfigurationTampering_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 350f,
            SuspiciousCommandCount = 3,
            FailedLoginRate = 0.1f,
            TrafficToEngineeringStationsRatio = 0.7f,
            PlcConfigChangeRate = 0.9f,
            HmiScreenChangeRate = 0.8f,
            EncryptedTrafficRatio = 0.2f,
            ExternalConnectionCount = 2,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.4f,
            DataExfiltrationVolume = 3f,
            CpuLoadAnomalyScore = 0.25f,
            ProcessValueAnomalyScore = 0.4f,
            ConnectionRate = 12f,
            DistinctProtocolCount = 4
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.ConfigurationTampering);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_DenialOfService_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 1400f,
            SuspiciousCommandCount = 2,
            FailedLoginRate = 0.15f,
            TrafficToEngineeringStationsRatio = 0.1f,
            PlcConfigChangeRate = 0.05f,
            HmiScreenChangeRate = 0.05f,
            EncryptedTrafficRatio = 0.15f,
            ExternalConnectionCount = 5,
            BroadcastTrafficRatio = 0.8f,
            ProtocolViolationScore = 0.3f,
            DataExfiltrationVolume = 2f,
            CpuLoadAnomalyScore = 0.9f,
            ProcessValueAnomalyScore = 0.5f,
            ConnectionRate = 150f,
            DistinctProtocolCount = 3
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.DenialOfService);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_RansomwareActivity_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 600f,
            SuspiciousCommandCount = 4,
            FailedLoginRate = 0.08f,
            TrafficToEngineeringStationsRatio = 0.25f,
            PlcConfigChangeRate = 0.15f,
            HmiScreenChangeRate = 0.2f,
            EncryptedTrafficRatio = 0.9f,
            ExternalConnectionCount = 10,
            BroadcastTrafficRatio = 0.12f,
            ProtocolViolationScore = 0.25f,
            DataExfiltrationVolume = 40f,
            CpuLoadAnomalyScore = 0.8f,
            ProcessValueAnomalyScore = 0.35f,
            ConnectionRate = 25f,
            DistinctProtocolCount = 5
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.RansomwareActivity);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_DataExfiltration_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 1200f,
            SuspiciousCommandCount = 1,
            FailedLoginRate = 0.05f,
            TrafficToEngineeringStationsRatio = 0.15f,
            PlcConfigChangeRate = 0.08f,
            HmiScreenChangeRate = 0.1f,
            EncryptedTrafficRatio = 0.6f,
            ExternalConnectionCount = 12,
            BroadcastTrafficRatio = 0.05f,
            ProtocolViolationScore = 0.15f,
            DataExfiltrationVolume = 100f,
            CpuLoadAnomalyScore = 0.3f,
            ProcessValueAnomalyScore = 0.15f,
            ConnectionRate = 18f,
            DistinctProtocolCount = 4
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.DataExfiltration);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_ManInTheMiddle_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 280f,
            SuspiciousCommandCount = 2,
            FailedLoginRate = 0.12f,
            TrafficToEngineeringStationsRatio = 0.2f,
            PlcConfigChangeRate = 0.1f,
            HmiScreenChangeRate = 0.12f,
            EncryptedTrafficRatio = 0.3f,
            ExternalConnectionCount = 3,
            BroadcastTrafficRatio = 0.7f,
            ProtocolViolationScore = 0.8f,
            DataExfiltrationVolume = 8f,
            CpuLoadAnomalyScore = 0.2f,
            ProcessValueAnomalyScore = 0.25f,
            ConnectionRate = 60f,
            DistinctProtocolCount = 10
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.ManInTheMiddle);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_ProtocolMisuse_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 30f,
            SuspiciousCommandCount = 8,
            FailedLoginRate = 0.08f,
            TrafficToEngineeringStationsRatio = 0.15f,
            PlcConfigChangeRate = 0.2f,
            HmiScreenChangeRate = 0.15f,
            EncryptedTrafficRatio = 0.08f,
            ExternalConnectionCount = 1,
            BroadcastTrafficRatio = 0.2f,
            ProtocolViolationScore = 0.9f,
            DataExfiltrationVolume = 2f,
            CpuLoadAnomalyScore = 0.15f,
            ProcessValueAnomalyScore = 0.2f,
            ConnectionRate = 10f,
            DistinctProtocolCount = 12
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.ProtocolMisuse);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_BruteForceAuthentication_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 150f,
            SuspiciousCommandCount = 1,
            FailedLoginRate = 0.85f,
            TrafficToEngineeringStationsRatio = 0.5f,
            PlcConfigChangeRate = 0.05f,
            HmiScreenChangeRate = 0.08f,
            EncryptedTrafficRatio = 0.25f,
            ExternalConnectionCount = 5,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.1f,
            DataExfiltrationVolume = 1f,
            CpuLoadAnomalyScore = 0.2f,
            ProcessValueAnomalyScore = 0.1f,
            ConnectionRate = 80f,
            DistinctProtocolCount = 2
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.BruteForceAuthentication);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_SuspiciousEngineeringWorkstationActivity_DetectsCorrectly()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 450f,
            SuspiciousCommandCount = 2,
            FailedLoginRate = 0.1f,
            TrafficToEngineeringStationsRatio = 0.85f,
            PlcConfigChangeRate = 0.7f,
            HmiScreenChangeRate = 0.8f,
            EncryptedTrafficRatio = 0.35f,
            ExternalConnectionCount = 7,
            BroadcastTrafficRatio = 0.1f,
            ProtocolViolationScore = 0.2f,
            DataExfiltrationVolume = 15f,
            CpuLoadAnomalyScore = 0.35f,
            ProcessValueAnomalyScore = 0.3f,
            ConnectionRate = 20f,
            DistinctProtocolCount = 5
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.ThreatType.Should().Be(IcsThreatType.SuspiciousEngineeringWorkstationActivity);
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.5);
    }

    [Fact]
    public void Classify_ReturnsExplanation_WithIndicators()
    {
        var features = new SensorFeatureVector
        {
            AveragePacketSize = 150f,
            SuspiciousCommandCount = 1,
            FailedLoginRate = 0.85f,
            TrafficToEngineeringStationsRatio = 0.5f,
            PlcConfigChangeRate = 0.05f,
            HmiScreenChangeRate = 0.08f,
            EncryptedTrafficRatio = 0.25f,
            ExternalConnectionCount = 5,
            BroadcastTrafficRatio = 0.08f,
            ProtocolViolationScore = 0.1f,
            DataExfiltrationVolume = 1f,
            CpuLoadAnomalyScore = 0.2f,
            ProcessValueAnomalyScore = 0.1f,
            ConnectionRate = 80f,
            DistinctProtocolCount = 2
        };

        var reading = CreateReading(features);
        var result = _classifier.Classify(reading);

        result.Explanation.Should().NotBeNullOrEmpty();
        result.Explanation.Should().Contain("Индикаторы:");
    }

    private static SensorReading CreateReading(SensorFeatureVector features)
    {
        return SensorReading.Create(SensorId.NewId(), features);
    }
}
