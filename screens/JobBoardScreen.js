// screens/JobBoardScreen.js
import React from 'react';
import { View, Text, FlatList, Button, StyleSheet } from 'react-native';

const jobs = [
  { id: '1', title: 'Nurse', description: 'Looking for an experienced nurse.' },
  { id: '2', title: 'Lab Technician', description: 'Required for immediate hiring.' },
  // Add more jobs here
];

export default function JobBoardScreen({ navigation }) {
  const renderItem = ({ item }) => (
    <View style={styles.item}>
      <Text>{item.title}</Text>
      <Text>{item.description}</Text>
      <Button title="View Details" onPress={() => navigation.navigate('JobDetails', { job: item })} />
    </View>
  );

  return (
    <View style={styles.container}>
      <Text>Job Board</Text>
      <FlatList
        data={jobs}
        renderItem={renderItem}
        keyExtractor={(item) => item.id}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 16,
  },
  item: {
    backgroundColor: '#f9c2ff',
    padding: 20,
    marginVertical: 8,
    marginHorizontal: 16,
  },
});
