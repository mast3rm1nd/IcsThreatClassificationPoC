using IcsThreatClassification.Domain.Abstractions;
using IcsThreatClassification.Domain.Configuration;
using IcsThreatClassification.Domain.Enums;
using IcsThreatClassification.Domain.Models;
using IcsThreatClassification.Domain.ValueObjects;

namespace IcsThreatClassification.MlEngine.Data;

/// <summary>
/// Генерирует синтетические размеченные наборы данных для обучения ML-модели.
/// </summary>
public sealed class SyntheticDatasetGenerator : ISyntheticDatasetGenerator
{
    public IReadOnlyCollection<LabeledSensorSample> Generate(SyntheticDatasetOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var random = options.Seed.HasValue ? new Random(options.Seed.Value) : new Random();
        var samples = new List<LabeledSensorSample>();

        var threatTypes = Enum.GetValues<IcsThreatType>();

        foreach (var threatType in threatTypes)
        {
            var profile = ThreatFeatureProfiles.GetProfile(threatType);

            for (int i = 0; i < options.SamplesPerThreatType; i++)
            {
                var features = GenerateFeatureVector(profile, random, options.NoiseLevel);
                samples.Add(new LabeledSensorSample(features, threatType));
            }
        }

        Shuffle(samples, random);

        return samples.AsReadOnly();
    }

    private static SensorFeatureVector GenerateFeatureVector(FeatureProfile profile, Random random, double noiseMultiplier)
    {
        return new SensorFeatureVector
        {
            AveragePacketSize = SampleGaussian(profile.AveragePacketSize, random, noiseMultiplier, 10f, 1500f),
            SuspiciousCommandCount = (int)Math.Max(0, SampleGaussian(profile.SuspiciousCommandCount, random, noiseMultiplier, 0f, 50f)),
            FailedLoginRate = SampleGaussian(profile.FailedLoginRate, random, noiseMultiplier, 0f, 1f),
            TrafficToEngineeringStationsRatio = SampleGaussian(profile.TrafficToEngineeringStationsRatio, random, noiseMultiplier, 0f, 1f),
            PlcConfigChangeRate = SampleGaussian(profile.PlcConfigChangeRate, random, noiseMultiplier, 0f, 1f),
            HmiScreenChangeRate = SampleGaussian(profile.HmiScreenChangeRate, random, noiseMultiplier, 0f, 1f),
            EncryptedTrafficRatio = SampleGaussian(profile.EncryptedTrafficRatio, random, noiseMultiplier, 0f, 1f),
            ExternalConnectionCount = (int)Math.Max(0, SampleGaussian(profile.ExternalConnectionCount, random, noiseMultiplier, 0f, 30f)),
            BroadcastTrafficRatio = SampleGaussian(profile.BroadcastTrafficRatio, random, noiseMultiplier, 0f, 1f),
            ProtocolViolationScore = SampleGaussian(profile.ProtocolViolationScore, random, noiseMultiplier, 0f, 1f),
            DataExfiltrationVolume = SampleGaussian(profile.DataExfiltrationVolume, random, noiseMultiplier, 0f, 200f),
            CpuLoadAnomalyScore = SampleGaussian(profile.CpuLoadAnomalyScore, random, noiseMultiplier, 0f, 1f),
            ProcessValueAnomalyScore = SampleGaussian(profile.ProcessValueAnomalyScore, random, noiseMultiplier, 0f, 1f),
            ConnectionRate = SampleGaussian(profile.ConnectionRate, random, noiseMultiplier, 0f, 200f),
            DistinctProtocolCount = (int)Math.Max(1, SampleGaussian(profile.DistinctProtocolCount, random, noiseMultiplier, 1f, 15f))
        };
    }

    private static float SampleGaussian(
        (float Mean, float StdDev) distribution,
        Random random,
        double noiseMultiplier,
        float min,
        float max)
    {
        double u1 = 1.0 - random.NextDouble();
        double u2 = 1.0 - random.NextDouble();
        double standardNormal = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);

        double scaledStdDev = distribution.StdDev * noiseMultiplier;
        double value = distribution.Mean + standardNormal * scaledStdDev;

        return (float)Math.Clamp(value, min, max);
    }

    private static void Shuffle<T>(List<T> list, Random random)
    {
        int n = list.Count;
        while (n > 1)
        {
            n--;
            int k = random.Next(n + 1);
            (list[k], list[n]) = (list[n], list[k]);
        }
    }
}
