using Microsoft.ML.Data;

namespace IcsThreatClassification.MlEngine.Training;

/// <summary>
/// Класс выходных данных ML.NET для предсказаний.
/// </summary>
internal sealed class MlPredictionData
{
    [ColumnName("PredictedLabel")]
    public uint PredictedLabel { get; set; }

    [ColumnName("Score")]
    public float[] Score { get; set; } = [];
}
