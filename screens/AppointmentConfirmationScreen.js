// screens/AppointmentConfirmationScreen.js
import React from 'react';
import { View, Text, Button, StyleSheet } from 'react-native';

export default function AppointmentConfirmationScreen({ route, navigation }) {
  const { doctor } = route.params;

  const handleConfirm = () => {
    // Implement appointment confirmation logic here
    navigation.navigate('Home');
  };

  return (
    <View style={styles.container}>
      <Text>Appointment Confirmation</Text>
      <Text>Doctor: {doctor.name}</Text>
      <Text>Specialty: {doctor.specialty}</Text>
      <Button title="Confirm" onPress={handleConfirm} />
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
