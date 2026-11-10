const categories = [
  { key: 'safe', label: 'Safe', color: '#16A34A' },
  { key: 'medium', label: 'Medium Risk', color: '#F59E0B' },
  { key: 'high', label: 'High Risk', color: '#EF4444' },
];

export function createRiskDistribution(levels = {}) {
  const values = categories.map(({ key }) => {
    const value = Number(levels[key]);
    return Number.isFinite(value) && value > 0 ? value : 0;
  });
  const total = values.reduce((sum, value) => sum + value, 0);
  return {
    total,
    categories: categories.map((category, index) => ({
      ...category,
      count: values[index],
      percentage: total ? (values[index] / total) * 100 : 0,
    })),
  };
}
