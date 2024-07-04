// screens/HealthcareRequestsScreen.js
import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet } from 'react-native';

export default function HealthcareRequestsScreen({ navigation }) {
  const [hospitalName, setHospitalName] = useState('');
  const [personnelNeeded, setPersonnelNeeded] = useState('');

  const handleSubmit = () => {
    // Implement healthcare request logic here
    navigation.goBack();
  };

  return (
    <View style={styles.container}>
      <Text>Request Healthcare Personnel</Text>
      <TextInput
        style={styles.input}
        placeholder="Hospital Name"
        value={hospitalName}
        onChangeText={setHospitalName}
      />
      <TextInput
        style={styles.input}
        placeholder="Personnel Needed"
        value={personnelNeeded}
        onChangeText={setPersonnelNeeded}
      />
      <Button title="Submit" onPress={handleSubmit} />
      <Button title="Back" onPress={() => navigation.goBack()} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 16,
  },
  input: {
    height: 40,
    borderColor: 'gray',
    borderWidth: 1,
    marginBottom: 12,
    paddingHorizontal: 8,
  },
});
