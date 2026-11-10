/**
 * WebShield - In-Browser Random Forest Inference Engine
 *
 * Privacy & Performance Guarantees:
 * - 100% Offline execution: zero remote calls, zero telemetry.
 * - Evaluates compact decision tree arrays in microsecond time.
 * - Usable in Node.js, service workers, and popup contexts.
 */

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.WebShieldModel = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /**
   * Recursively traverses a decision tree node to return the leaf probability.
   * Node format: [featureIndex, threshold, leftChildNode, rightChildNode, leafProbability]
   *
   * @param {Array} node - Tree node array.
   * @param {Array<number>} featureVector - Ordered numerical feature vector.
   * @returns {number} Leaf phishing probability (0.0 to 1.0).
   */
  function evaluateTree(node, featureVector) {
    // If leaf node (node[4] contains leaf probability)
    if (node[4] !== null && node[4] !== undefined) {
      return node[4];
    }

    const featureIdx = node[0];
    const threshold = node[1];

    if (featureVector[featureIdx] <= threshold) {
      return evaluateTree(node[2], featureVector);
    } else {
      return evaluateTree(node[3], featureVector);
    }
  }

  /**
   * Computes the ensemble average phishing probability across all trees.
   *
   * @param {object} model - Parsed model JSON object containing trees array.
   * @param {Array<number>} featureVector - Numerical feature vector matching model.features.
   * @returns {number} Average phishing probability between 0.0 and 1.0.
   */
  function predictProbability(model, featureVector) {
    if (!model || !Array.isArray(model.trees) || model.trees.length === 0) {
      throw new Error('[WebShieldModel] Invalid or uninitialized model payload.');
    }
    if (!Array.isArray(featureVector)) {
      throw new Error('[WebShieldModel] featureVector must be an array of numerical values.');
    }

    let totalProbability = 0;
    const trees = model.trees;
    const numTrees = trees.length;

    for (let i = 0; i < numTrees; i++) {
      totalProbability += evaluateTree(trees[i], featureVector);
    }

    const avg = totalProbability / numTrees;
    return Number(avg.toFixed(4));
  }

  /**
   * Converts a feature dictionary (from WebShieldFeatures.extractFeatures)
   * into the exact ordered numerical vector expected by the model.
   *
   * @param {object} model - Parsed model payload with .features list.
   * @param {object} featureDict - Feature dictionary from extractFeatures.
   * @returns {Array<number>} Ordered numerical feature vector.
   */
  function buildFeatureVector(model, featureDict) {
    const featureNames = model.features || [];
    return featureNames.map((name) => {
      const val = featureDict[name];
      if (typeof val === 'boolean') return val ? 1 : 0;
      if (typeof val === 'number') return val;
      if (val === null || val === undefined) return 0;
      return Number(val) || 0;
    });
  }

  return {
    evaluateTree,
    predictProbability,
    buildFeatureVector
  };
});
