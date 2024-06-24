% RMSE value to be 8.0105e-17

function [trainedModel, validationRMSE] = trainRegressionModel(trainingData)
inputTable = array2table(trainingData, 'VariableNames', {'column_1', 'column_2'});

predictorNames = {'column_2'};
predictors = inputTable(:, predictorNames);
response = inputTable.column_1;
isCategoricalPredictor = [false];

regressionTree = fitrtree(...
    predictors, ...
    response, ...
    'MinLeafSize', 1, ...
    'Surrogate', 'off');

predictorExtractionFcn = @(x) array2table(x, 'VariableNames', predictorNames);
treePredictFcn = @(x) predict(regressionTree, x);
trainedModel.predictFcn = @(x) treePredictFcn(predictorExtractionFcn(x));

trainedModel.RegressionTree = regressionTree;
trainedModel.About = 'This struct is a trained model exported from Regression Learner R2020b.';
trainedModel.HowToPredict = sprintf('To make predictions on a new predictor column matrix, X, use: \n  yfit = c.predictFcn(X) \nreplacing ''c'' with the name of the variable that is this struct, e.g. ''trainedModel''. \n \nX must contain exactly 1 columns because this model was trained using 1 predictors. \nX must contain only predictor columns in exactly the same order and format as your training \ndata. Do not include the response column or any columns you did not import into the app. \n \nFor more information, see <a href="matlab:helpview(fullfile(docroot, ''stats'', ''stats.map''), ''appregression_exportmodeltoworkspace'')">How to predict using an exported model</a>.');

inputTable = array2table(trainingData, 'VariableNames', {'column_1', 'column_2'});

predictorNames = {'column_2'};
predictors = inputTable(:, predictorNames);
response = inputTable.column_1;
isCategoricalPredictor = [false];

partitionedModel = crossval(trainedModel.RegressionTree, 'KFold', 50);

validationPredictions = kfoldPredict(partitionedModel);

validationRMSE = sqrt(kfoldLoss(partitionedModel, 'LossFun', 'mse'));
