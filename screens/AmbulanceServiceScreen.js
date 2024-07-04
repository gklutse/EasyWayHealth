// screens/AmbulanceServiceScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function AmbulanceServiceScreen({ navigation }) {
  const handleRequest = () => {
    // Implement ambulance request logic here
  };

  return (
    <View style={styles.container}>
      <Text>Request an Ambulance</Text>
      <Button title="Request" onPress={handleRequest} />
      <Button title="Back" onPress={() => navigation.goBack()} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
});
