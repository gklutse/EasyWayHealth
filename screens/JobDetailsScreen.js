// screens/JobDetailsScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function JobDetailsScreen({ route, navigation }) {
  const { job } = route.params;

  return (
    <View style={styles.container}>
      <Text>{job.title}</Text>
      <Text>{job.description}</Text>
      <Button title="Apply" onPress={() => {/* Implement job application logic here */}} />
      <Button title="Back" onPress={() => navigation.goBack()} />
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
});
