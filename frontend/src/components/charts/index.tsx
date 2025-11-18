import React from 'react';
import { Line, Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  ChartOptions,
} from 'chart.js';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

// Define chart color palette
const chartColors = [
  'rgba(75, 192, 192, 0.6)',
  'rgba(255, 99, 132, 0.6)',
  'rgba(54, 162, 235, 0.6)',
  'rgba(255, 206, 86, 0.6)',
  'rgba(153, 102, 255, 0.6)',
  'rgba(255, 159, 64, 0.6)',
];

// Line Chart Component
interface LineChartProps {
  data: any[];
  xKey: string;
  yKey: string;
  categories?: string[];
  title?: string;
  height?: number;
}

export const LineChart: React.FC<LineChartProps> = ({
  data,
  xKey,
  yKey,
  categories = [],
  title,
  height,
}) => {
  // Process data for single or multi-category line chart
  const chartData = {
    labels: data.map(item => item[xKey]),
    datasets: categories.length > 0
      ? categories.map((category, index) => ({
          label: category,
          data: data.map(item => item[category.toLowerCase()]),
          borderColor: chartColors[index % chartColors.length],
          backgroundColor: chartColors[index % chartColors.length].replace('0.6', '0.1'),
          borderWidth: 2,
          tension: 0.3,
          fill: true,
        }))
      : [
          {
            label: yKey,
            data: data.map(item => item[yKey]),
            borderColor: chartColors[0],
            backgroundColor: chartColors[0].replace('0.6', '0.1'),
            borderWidth: 2,
            tension: 0.3,
            fill: true,
          },
        ],
  };

  const options: ChartOptions<'line'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: !!title,
        text: title || '',
      },
      tooltip: {
        mode: 'index',
        intersect: false,
      },
    },
    scales: {
      y: {
        beginAtZero: true,
      },
    },
    interaction: {
      mode: 'nearest',
      axis: 'x',
      intersect: false,
    },
  };

  return (
    <div style={{ height: height || '100%', width: '100%' }}>
      <Line data={chartData} options={options} />
    </div>
  );
};

// Bar Chart Component
interface BarChartProps {
  data: any[];
  xKey: string;
  yKey: string;
  categories?: string[];
  title?: string;
  stacked?: boolean;
  horizontal?: boolean;
  height?: number;
}

export const BarChart: React.FC<BarChartProps> = ({
  data,
  xKey,
  yKey,
  categories = [],
  title,
  stacked = false,
  horizontal = false,
  height,
}) => {
  const chartData = {
    labels: data.map(item => item[xKey]),
    datasets: categories.length > 0
      ? categories.map((category, index) => ({
          label: category,
          data: data.map(item => item[category.toLowerCase()]),
          backgroundColor: chartColors[index % chartColors.length],
          borderWidth: 1,
        }))
      : [
          {
            label: yKey,
            data: data.map(item => item[yKey]),
            backgroundColor: chartColors[0],
            borderWidth: 1,
          },
        ],
  };

  const options: ChartOptions<'bar'> = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: horizontal ? 'y' : 'x',
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: !!title,
        text: title || '',
      },
    },
    scales: {
      x: {
        stacked: stacked,
      },
      y: {
        stacked: stacked,
        beginAtZero: true,
      },
    },
  };

  return (
    <div style={{ height: height || '100%', width: '100%' }}>
      <Bar data={chartData} options={options} />
    </div>
  );
};

// Pie Chart Component
interface PieChartProps {
  data: any[];
  nameKey: string;
  valueKey: string;
  title?: string;
  height?: number;
}

export const PieChart: React.FC<PieChartProps> = ({
  data,
  nameKey,
  valueKey,
  title,
  height,
}) => {
  const chartData = {
    labels: data.map(item => item[nameKey]),
    datasets: [
      {
        data: data.map(item => item[valueKey]),
        backgroundColor: data.map((_, index) => chartColors[index % chartColors.length]),
        borderWidth: 1,
      },
    ],
  };

  const options: ChartOptions<'pie'> = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'right' as const,
      },
      title: {
        display: !!title,
        text: title || '',
      },
    },
  };

  return (
    <div style={{ height: height || '100%', width: '100%' }}>
      <Pie data={chartData} options={options} />
    </div>
  );
};